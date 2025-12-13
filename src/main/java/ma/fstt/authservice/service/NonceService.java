package ma.fstt.authservice.service;

import ma.fstt.authservice.exception.InvalidSignatureException;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de gestion des nonces MetaMask
 */
@Service
public class NonceService {

    private final UserServiceClient userServiceClient;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public NonceService(UserServiceClient userServiceClient) {
        this.userServiceClient = userServiceClient;
    }

    /**
     * Génère un nonce cryptographiquement sécurisé et le stocke
     */
    public String generateAndStoreNonce(String wallet) {
        byte[] nonceBytes = new byte[32];
        SECURE_RANDOM.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);

        // Stocker le nonce via UserManagementService
        userServiceClient.storeNonce(wallet, nonce);

        return nonce;
    }

    /**
     * Récupère et valide le nonce (sans le supprimer)
     */
    public String getNonce(String wallet) {
        String nonce = userServiceClient.getNonce(wallet);

        if (nonce == null || nonce.isEmpty()) {
            throw new InvalidSignatureException("Nonce invalide ou expiré");
        }

        return nonce;
    }

    /**
     * Supprime le nonce après utilisation réussie
     */
    public void deleteNonce(String wallet) {
        userServiceClient.deleteNonce(wallet);
    }
}