package ma.fstt.authservice.model;

import java.util.List;

/**
 * DTO représentant un utilisateur
 */
public record UserDto(
        Long id,
        String wallet,
        String username,
        String email,
        String role,
        boolean enabled
) {}