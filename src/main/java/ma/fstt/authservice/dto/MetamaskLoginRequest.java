package ma.fstt.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Requête de login MetaMask
 */
public record MetamaskLoginRequest(
        @NotBlank(message = "Le wallet ne peut pas être vide")
        @Pattern(regexp = "^0x[0-9a-fA-F]{40}$", message = "Format de wallet invalide")
        String wallet,

        @NotBlank(message = "La signature ne peut pas être vide")
        String signature
) {}

