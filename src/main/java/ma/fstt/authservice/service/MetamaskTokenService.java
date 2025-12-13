package ma.fstt.authservice.service;

import ma.fstt.authservice.dto.TokenResponse;
import ma.fstt.authservice.model.UserDto;
import ma.fstt.authservice.security.MetamaskUserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext; // <--- Import
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings; // <--- Import
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.Instant;
import java.util.Set;

@Service
public class MetamaskTokenService {

    private static final Logger log = LoggerFactory.getLogger(MetamaskTokenService.class);

    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final UserServiceClient userServiceClient;
    private final AuthorizationServerSettings authorizationServerSettings; // <--- 1. Nouveau champ

    public MetamaskTokenService(
            OAuth2TokenGenerator<?> tokenGenerator,
            OAuth2AuthorizationService authorizationService,
            RegisteredClientRepository clientRepository,
            UserServiceClient userServiceClient,
            AuthorizationServerSettings authorizationServerSettings) { // <--- 2. Injection dans le constructeur
        this.tokenGenerator = tokenGenerator;
        this.authorizationService = authorizationService;
        this.clientRepository = clientRepository;
        this.userServiceClient = userServiceClient;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    public TokenResponse generateTokens(String wallet, String signature) {
        log.info("🎫 Génération des tokens pour wallet: {}", wallet);

        RegisteredClient client = clientRepository.findByClientId("authentification-service-client");
        if (client == null) {
            throw new RuntimeException("Client OAuth2 non trouvé");
        }

        UserDto user = userServiceClient.getUserByWallet(wallet);
        MetamaskUserPrincipal principal = new MetamaskUserPrincipal(user);

        Set<String> authorizedScopes = Set.of(
                OidcScopes.OPENID,
                OidcScopes.PROFILE,
                "read",
                "write"
        );

        // --- 3. CRÉATION MANUELLE DU CONTEXTE ---
        // On ne peut pas utiliser AuthorizationServerContextHolder.getContext() car il est null ici
        AuthorizationServerContext authorizationServerContext = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return authorizationServerSettings.getIssuer();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        };
        // ----------------------------------------

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(principal)
                .authorizationServerContext(authorizationServerContext) // <--- 4. Utilisation du contexte manuel
                .authorizationGrantType(new AuthorizationGrantType("metamask"))
                .authorizedScopes(authorizedScopes);

        // ... Le reste de la méthode reste identique ...

        // 5. Génération Access Token
        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Cannot generate Access Token", null)
            );
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes
        );

        // 6. Génération Refresh Token
        OAuth2RefreshToken refreshToken = null;
        if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
            if (generatedRefreshToken != null) {
                refreshToken = new OAuth2RefreshToken(
                        generatedRefreshToken.getTokenValue(),
                        generatedRefreshToken.getIssuedAt(),
                        generatedRefreshToken.getExpiresAt()
                );
            }
        }

        // 7. Génération ID Token
        OidcIdToken idToken;
        if (authorizedScopes.contains(OidcScopes.OPENID)) {
            OAuth2TokenContext idTokenContext = tokenContextBuilder
                    .tokenType(new OAuth2TokenType(OidcParameterNames.ID_TOKEN))
                    .put(OAuth2AccessToken.class, accessToken)
                    .build();

            OAuth2Token generatedIdToken = tokenGenerator.generate(idTokenContext);
            if (generatedIdToken instanceof Jwt jwt) {
                idToken = new OidcIdToken(
                        jwt.getTokenValue(),
                        jwt.getIssuedAt(),
                        jwt.getExpiresAt(),
                        jwt.getClaims()
                );
            } else {
                idToken = null;
            }
        } else {
            idToken = null;
        }

        // 8. Sauvegarde Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(client)
                .principalName(wallet)
                .authorizationGrantType(new AuthorizationGrantType("metamask"))
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), principal);

        if (generatedAccessToken instanceof Jwt jwt) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims())
            );
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        if (refreshToken != null) {
            authorizationBuilder.token(refreshToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false)
            );
        }

        if (idToken != null) {
            authorizationBuilder.token(idToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims())
            );
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        log.info("✅ Tokens générés et sauvegardés avec succès");

        Long expiresIn = null;
        if (accessToken.getExpiresAt() != null && accessToken.getIssuedAt() != null) {
            expiresIn = accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
        }

        return new TokenResponse(
                accessToken.getTokenValue(),
                refreshToken != null ? refreshToken.getTokenValue() : null,
                "Bearer",
                expiresIn,
                idToken != null ? idToken.getTokenValue() : null
        );
    }

    public TokenResponse refreshTokens(String refreshTokenValue) {
        log.info("🔄 Rafraîchissement des tokens");

        RegisteredClient client = clientRepository.findByClientId("authentification-service-client");
        if (client == null) {
            throw new RuntimeException("Client OAuth2 non trouvé");
        }

        OAuth2Authorization authorization = authorizationService.findByToken(
                refreshTokenValue,
                OAuth2TokenType.REFRESH_TOKEN
        );

        if (authorization == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid refresh token", null)
            );
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getRefreshToken();

        if (refreshToken == null || !refreshToken.isActive()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token expired", null)
            );
        }

        Object principalObj = authorization.getAttribute(Principal.class.getName());
        MetamaskUserPrincipal principal;

        if (principalObj instanceof MetamaskUserPrincipal) {
            principal = (MetamaskUserPrincipal) principalObj;
        } else {
            String wallet = authorization.getPrincipalName();
            UserDto user = userServiceClient.getUserByWallet(wallet);
            principal = new MetamaskUserPrincipal(user);
        }

        Set<String> authorizedScopes = authorization.getAuthorizedScopes();

        // --- MÊME CORRECTION ICI POUR LE REFRESH ---
        AuthorizationServerContext authorizationServerContext = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return authorizationServerSettings.getIssuer();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        };
        // -------------------------------------------

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(principal)
                .authorizationServerContext(authorizationServerContext) // <--- Utilisation ici aussi
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizedScopes(authorizedScopes)
                .authorization(authorization);

        // ... Le reste de refreshTokens reste identique ...

        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Cannot generate Access Token", null)
            );
        }

        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes
        );

        OAuth2RefreshToken newRefreshToken = null;
        if (!client.getTokenSettings().isReuseRefreshTokens()) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
            if (generatedRefreshToken != null) {
                newRefreshToken = new OAuth2RefreshToken(
                        generatedRefreshToken.getTokenValue(),
                        generatedRefreshToken.getIssuedAt(),
                        generatedRefreshToken.getExpiresAt()
                );
            }
        } else {
            newRefreshToken = refreshToken.getToken();
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

        if (generatedAccessToken instanceof Jwt jwt) {
            authorizationBuilder.token(newAccessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims())
            );
        } else {
            authorizationBuilder.accessToken(newAccessToken);
        }

        if (newRefreshToken != null) {
            authorizationBuilder.token(newRefreshToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false)
            );
        }

        OAuth2Authorization updatedAuthorization = authorizationBuilder.build();
        authorizationService.save(updatedAuthorization);

        log.info("✅ Tokens rafraîchis avec succès");

        Long expiresIn = null;
        if (newAccessToken.getExpiresAt() != null && newAccessToken.getIssuedAt() != null) {
            expiresIn = newAccessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
        }

        return new TokenResponse(
                newAccessToken.getTokenValue(),
                newRefreshToken != null ? newRefreshToken.getTokenValue() : null,
                "Bearer",
                expiresIn,
                null
        );
    }
}