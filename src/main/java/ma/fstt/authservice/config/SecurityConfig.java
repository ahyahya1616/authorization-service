package ma.fstt.authservice.config;

import ma.fstt.authservice.security.MetamaskAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration Spring Security pour le Spring Authorization Server
 * ✅ ORDER 2 = S'applique après l'Authorization Server Filter Chain
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final MetamaskAuthenticationProvider metamaskAuthenticationProvider;

    public SecurityConfig(MetamaskAuthenticationProvider metamaskAuthenticationProvider) {
        this.metamaskAuthenticationProvider = metamaskAuthenticationProvider;
    }

    /**
     * Security Filter Chain pour les endpoints publics du SAS
     * ORDER 2 = Priorité après le Authorization Server
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // ✅ Endpoints OAuth2 publics (JWKS, discovery, userinfo)
                        .requestMatchers("/oauth2/jwks").permitAll()
                        .requestMatchers("/.well-known/**").permitAll()
                        .requestMatchers("/userinfo").permitAll()
                        .requestMatchers("/api/auth/metamask/**").permitAll()
                        // ✅ Health check et actuator
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/actuator/info").permitAll()
                        .requestMatchers("/actuator/env").permitAll()

                        // ✅ Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                // ✅ Sessions stateless pour une API REST
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // ✅ Désactiver form login
                .formLogin(form -> form.disable())

                // ✅ HTTP Basic pour les clients OAuth2
                .httpBasic(Customizer.withDefaults())

                // ✅ Désactiver CSRF (API REST avec tokens)
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

    /**
     * AuthenticationManager avec le provider custom MetaMask
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(metamaskAuthenticationProvider);
    }
}