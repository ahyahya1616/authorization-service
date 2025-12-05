package ma.fstt.authservice.config;

import ma.fstt.authservice.model.UserDto;
import ma.fstt.authservice.security.MetamaskUserPrincipal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;

@Configuration
public class JwtCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {

            // Appliquer uniquement pour l'access token
            if (!"access_token".equals(context.getTokenType().getValue())) {
                return;
            }

            var principal = context.getPrincipal();
            var wallet = principal.getName(); // le wallet est le "username"
            context.getClaims().claim("wallet", wallet);


            if (principal instanceof MetamaskUserPrincipal p) {
                context.getClaims().claim("id", p.getUser().id());
                context.getClaims().claim("email", p.getUser().email());
                context.getClaims().claim("role", p.getUser().role());
            }

        };
    }
}
