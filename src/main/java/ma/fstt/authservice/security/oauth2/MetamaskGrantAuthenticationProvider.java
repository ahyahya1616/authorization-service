package ma.fstt.authservice.security.oauth2;

import ma.fstt.authservice.exception.InvalidSignatureException;
import ma.fstt.authservice.exception.UserNotFoundException;
import ma.fstt.authservice.model.UserDto;
import ma.fstt.authservice.security.MetamaskUserPrincipal;
import ma.fstt.authservice.service.SignatureVerificationService;
import ma.fstt.authservice.service.UserServiceClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class MetamaskGrantAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final SignatureVerificationService signatureVerificationService;
    private final UserServiceClient userServiceClient;

    public MetamaskGrantAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            SignatureVerificationService signatureVerificationService,
            UserServiceClient userServiceClient) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.signatureVerificationService = signatureVerificationService;
        this.userServiceClient = userServiceClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MetamaskGrantAuthenticationToken metamaskAuth =
                (MetamaskGrantAuthenticationToken) authentication;

        // 1. Récupérer et valider le client
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(metamaskAuth);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 2. Authentifier l'utilisateur via MetaMask
        String wallet = metamaskAuth.getWallet();
        String signature = metamaskAuth.getSignature();

         signatureVerificationService.verifySignature(wallet, signature);

        // 3. Récupérer l'utilisateur
        UserDto user;
        try {
            user = userServiceClient.getUserByWallet(wallet);
        } catch (Exception e) {
            throw new UserNotFoundException("Utilisateur non trouvé pour le wallet : " + wallet);
        }

        MetamaskUserPrincipal principal = new MetamaskUserPrincipal(user);

        // 4. Scopes
        Set<String> authorizedScopes = registeredClient.getScopes();
        if (!metamaskAuth.getScopes().isEmpty()) {
            authorizedScopes = metamaskAuth.getScopes().stream()
                    .filter(registeredClient.getScopes()::contains)
                    .collect(Collectors.toSet());
        }

        // 5. Contexte de génération de token
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)
                .authorizedScopes(authorizedScopes);

        // --- GÉNÉRATION DES TOKENS ---

        // A. Access Token
        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Cannot generate Access Token", null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                accessTokenContext.getAuthorizedScopes());

        // B. Refresh Token (si supporté)
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(refreshTokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    refreshToken = new OAuth2RefreshToken(
                            generatedRefreshToken.getTokenValue(),
                            generatedRefreshToken.getIssuedAt(),
                            generatedRefreshToken.getExpiresAt());
                } else {
                    refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                }
            }
        }

        // C. ID Token (FIX CRITIQUE : requis si scope openid présent)
        OidcIdToken idToken;
        if (authorizedScopes.contains(OidcScopes.OPENID)) {
            OAuth2TokenContext idTokenContext = tokenContextBuilder
                    .tokenType(new OAuth2TokenType(OidcParameterNames.ID_TOKEN))
                    // Nécessaire pour lier l'ID Token à l'Access Token (at_hash)
                    .authorizationGrant(metamaskAuth)
                    .put(OAuth2AccessToken.class, accessToken)
                    .build();

            OAuth2Token generatedIdToken = this.tokenGenerator.generate(idTokenContext);
            if (generatedIdToken instanceof Jwt) {
                Jwt jwt = (Jwt) generatedIdToken;
                idToken = new OidcIdToken(
                        jwt.getTokenValue(),
                        jwt.getIssuedAt(),
                        jwt.getExpiresAt(),
                        jwt.getClaims());
            } else {
                idToken = null;
            }
        } else {
            idToken = null;
        }

        // 6. Sauvegarder l'Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(wallet)
                .authorizationGrantType(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), principal);

        // Sauvegarde Access Token AVEC ses claims (important pour le refresh)
        if (generatedAccessToken instanceof Jwt) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((Jwt) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // Sauvegarde Refresh Token
        if (refreshToken != null) {
            authorizationBuilder.token(refreshToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false));
        }

        // Sauvegarde ID Token (NOUVEAU)
        if (idToken != null) {
            authorizationBuilder.token(idToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        // 7. Retourner le résultat avec tous les tokens
        Map<String, Object> additionalParameters = java.util.Collections.emptyMap();
        if (idToken != null) {
            additionalParameters = Map.of(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
        }

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParameters
        );
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MetamaskGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}