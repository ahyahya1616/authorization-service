package ma.fstt.authservice.security;

import ma.fstt.authservice.exception.InvalidSignatureException;
import ma.fstt.authservice.exception.UserNotFoundException;
import ma.fstt.authservice.model.UserDto;
import ma.fstt.authservice.service.SignatureVerificationService;
import ma.fstt.authservice.service.UserServiceClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * AuthenticationProvider custom pour MetaMask
 * Remplace le UserDetailsService traditionnel
 */
@Component
public class MetamaskAuthenticationProvider implements AuthenticationProvider {

    private final SignatureVerificationService signatureVerificationService;
    private final UserServiceClient userServiceClient;

    public MetamaskAuthenticationProvider(
            SignatureVerificationService signatureVerificationService,
            UserServiceClient userServiceClient) {
        this.signatureVerificationService = signatureVerificationService;
        this.userServiceClient = userServiceClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MetamaskAuthenticationToken token = (MetamaskAuthenticationToken) authentication;

        String wallet = token.getWallet();
        String signature = token.getSignature();
        String email = token.getEmail();

        // 1. Vérifier la signature cryptographique
         signatureVerificationService.verifySignature(wallet, signature);


        // 2. Récupérer l'utilisateur depuis UserManagementService
        UserDto user;
        try {
            user = userServiceClient.getUserByWallet(wallet);
        } catch (Exception e) {
            throw new UserNotFoundException("Utilisateur non trouvé pour le wallet : " + wallet);
        }

        // 3. Construire les authorities (rôles)
        var authorities = List.of(new SimpleGrantedAuthority(user.role()));


        // 4. Retourner une Authentication réussie
        return new MetamaskAuthenticationToken(
                wallet,
                signature,
                email,
                authorities
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MetamaskAuthenticationToken.class.isAssignableFrom(authentication);
    }
}