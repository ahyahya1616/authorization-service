package ma.fstt.authservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import ma.fstt.authservice.security.oauth2.MetamaskGrantAuthenticationConverter;
import ma.fstt.authservice.security.oauth2.MetamaskGrantAuthenticationProvider;
import ma.fstt.authservice.service.SignatureVerificationService;
import ma.fstt.authservice.service.UserServiceClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Configuration complète de Spring Authorization Server
 * Avec support du Custom Grant Type "metamask"
 */
@Configuration
public class AuthorizationServerConfig {

    private final SignatureVerificationService signatureVerificationService;
    private final UserServiceClient userServiceClient;

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    public AuthorizationServerConfig(
            SignatureVerificationService signatureVerificationService,
            UserServiceClient userServiceClient
            ){
        this.signatureVerificationService = signatureVerificationService;
        this.userServiceClient = userServiceClient;
    }


    /**
     * Security Filter Chain pour les endpoints OAuth2 Authorization Server
     * ORDER 1 = Priorité maximale
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // ✅ Configuration du Token Endpoint avec le Custom Grant Type "metamask"
        authorizationServerConfigurer
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        // Ajouter le converter pour grant_type=metamask
                        .accessTokenRequestConverter(
                                new MetamaskGrantAuthenticationConverter()
                        )
                        // Ajouter le provider qui traite l'authentification MetaMask
                        .authenticationProvider(
                                new MetamaskGrantAuthenticationProvider(
                                        authorizationService,
                                        tokenGenerator,
                                        signatureVerificationService,
                                        userServiceClient
                                )
                        )
                );

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                // Support OpenID Connect
                                .oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests((authorize) ->
                        // Le token endpoint DOIT être accessible anonymement
                        // pour que le ClientAuthenticationFilter puisse traiter le client_id
                        authorize
                                .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/oauth2/**").permitAll()
                                .requestMatchers("/oauth2/token").permitAll()

                                // Le reste (authorize, jwks, etc.) doit aussi être permis si nécessaire
                                // Le Token Endpoint /oauth2/token doit impérativement être public
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/metamask/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        authorizationServerConfigurer.getEndpointsMatcher()
                ));

        return http.build();
    }

    /**
     * Génère ou charge une paire de clés RSA pour signer les JWT
     * ⚠️ IMPORTANT: En production, persister les clés pour éviter l'invalidation
     * des tokens à chaque redémarrage
     */
    @Bean
    public KeyPair keyPair() {

        if (System.getenv("JWT_PRIVATE_KEY") != null && System.getenv("JWT_PUBLIC_KEY") != null) {
            try {
                return loadKeyPairFromEnv(
                        System.getenv("JWT_PRIVATE_KEY"),
                        System.getenv("JWT_PUBLIC_KEY")
                );
            } catch (Exception e) {
                throw new IllegalStateException("Impossible de charger les clés depuis les variables d'environnement", e);
            }
        }

        File keyFile = new File("config/keys/keypair.ser");

        // Charger les clés existantes si disponibles
        if (keyFile.exists()) {
            try {
                return loadKeyPairFromFile(keyFile);
            } catch (Exception e) {
                System.err.println("Erreur lors du chargement des clés, génération de nouvelles clés");
            }
        }

        // Générer de nouvelles clés
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Sauvegarder pour réutilisation
            saveKeyPairToFile(keyPair, keyFile);

            return keyPair;
        } catch (Exception ex) {
            throw new IllegalStateException("Impossible de générer la paire RSA", ex);
        }
    }

            /**
             * recuperer les cles depuis les varibales d'env
             *
             * **/
    private KeyPair loadKeyPairFromEnv(String privateKeyPem, String publicKeyPem) throws Exception {
        byte[] privateBytes = PemUtils.parsePrivateKey(privateKeyPem);
        byte[] publicBytes = PemUtils.parsePublicKey(publicKeyPem);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicBytes));
        return new KeyPair(publicKey, privateKey);
    }


    /**
     * Sauvegarde la paire de clés dans un fichier
     */
    private void saveKeyPairToFile(KeyPair keyPair, File file) {
        try {
            file.getParentFile().mkdirs();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                oos.writeObject(keyPair.getPrivate().getEncoded());
                oos.writeObject(keyPair.getPublic().getEncoded());
            }
            System.out.println("✅ Clés RSA sauvegardées dans : " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("⚠️ Impossible de sauvegarder les clés : " + e.getMessage());
        }
    }

    /**
     * Charge la paire de clés depuis un fichier
     */
    private KeyPair loadKeyPairFromFile(File file) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
            byte[] privateKeyBytes = (byte[]) ois.readObject();
            byte[] publicKeyBytes = (byte[]) ois.readObject();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = keyFactory.generatePrivate(
                    new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes)
            );
            PublicKey publicKey = keyFactory.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(publicKeyBytes)
            );

            System.out.println("✅ Clés RSA chargées depuis : " + file.getAbsolutePath());
            return new KeyPair(publicKey, privateKey);
        }
    }

    /**
     * JWK Source pour exposer les clés publiques via /oauth2/jwks
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // KeyID fixe en prod, aléatoire en dev
        String keyId = (System.getenv("JWT_PRIVATE_KEY") != null) ? "prod-key" : UUID.randomUUID().toString();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
//
//    /**
//     * JWT Decoder pour valider les tokens en interne
//     */
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }

    /**
     * JWT Encoder utilisé par le TokenGenerator
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * OAuth2 Token Generator - Génère access_token et refresh_token
     * ✅ Avec customizer pour ajouter des claims personnalisés
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }


    /**
     * Service de stockage des autorisations OAuth2
     * ⚠️ En mémoire pour dev, utiliser une DB en production
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * Configuration des endpoints Authorization Server
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcClientRegistrationEndpoint("/connect/register")
                .build();
    }
}