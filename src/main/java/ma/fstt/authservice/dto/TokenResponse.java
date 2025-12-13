package ma.fstt.authservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Réponse contenant les tokens OAuth2
 */
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") Long expiresIn,
        @JsonProperty("id_token") String idToken
) {}

