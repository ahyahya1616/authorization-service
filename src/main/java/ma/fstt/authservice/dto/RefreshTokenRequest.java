package ma.fstt.authservice.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Requête de refresh token
 */
public record RefreshTokenRequest(
        @NotBlank(message = "Le refresh token ne peut pas être vide")
        String refreshToken
) {}
