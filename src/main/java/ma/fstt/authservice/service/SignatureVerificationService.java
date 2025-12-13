package ma.fstt.authservice.service;

import ma.fstt.authservice.exception.InvalidSignatureException;
import ma.fstt.authservice.utils.Web3SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service de vérification des signatures MetaMask
 * ✅ CORRECTION: Ne supprime plus le nonce avant vérification
 */
@Service
public class SignatureVerificationService {

    private static final Logger log = LoggerFactory.getLogger(SignatureVerificationService.class);

    @Value("${app.metamask.signature-message-prefix}")
    private String messagePrefix;

    private final UserServiceClient userServiceClient;

    public SignatureVerificationService(UserServiceClient userServiceClient) {
        this.userServiceClient = userServiceClient;
    }

    /**
     * Vérifie que la signature correspond au nonce et au wallet
     * ✅ IMPORTANT: Cette méthode récupère le nonce SANS le supprimer
     */
    public void verifySignature(String wallet, String signature) {
        log.info("Vérification de la signature pour wallet: {}", wallet);

        // ✅ Récupérer le nonce SANS le supprimer
        String nonce = userServiceClient.getNonce(wallet);

        if (nonce == null || nonce.isEmpty()) {
            log.error("Nonce non trouvé ou expiré pour wallet: {}", wallet);
            throw new InvalidSignatureException("Nonce invalide ou expiré");
        }

        log.debug("Nonce récupéré: {}", nonce);

        // Créer le message signé (EXACTEMENT comme dans le frontend)
        String message = messagePrefix + nonce;
        log.debug("Message à vérifier: {}", message);

        try {
            // Vérifier la signature ECDSA
            String recoveredAddress = Web3SignatureUtils.ecRecover(message, signature);
            log.debug("Adresse récupérée: {}, Adresse attendue: {}", recoveredAddress, wallet);

            // Comparer l'adresse récupérée avec le wallet (case-insensitive)
            boolean isValid = wallet.equalsIgnoreCase(recoveredAddress);

            if (!isValid) {
                log.error("Signature invalide: adresse récupérée ({}) != wallet ({})",
                        recoveredAddress, wallet);
                throw new InvalidSignatureException(
                        "Signature invalide : adresse récupérée ne correspond pas"
                );
            }

            log.info("✅ Signature valide pour wallet: {}", wallet);

            // CORRECTION CRITIQUE: Supprimer le nonce SEULEMENT après vérification réussie
            userServiceClient.deleteNonce(wallet);
            log.debug("Nonce supprimé après vérification réussie");


        } catch (InvalidSignatureException e) {
            // Ne pas supprimer le nonce en cas d'échec pour permettre une nouvelle tentative
            log.error("Échec de vérification de signature: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Erreur lors de la vérification de signature", e);
            throw new InvalidSignatureException("Erreur lors de la vérification : " + e.getMessage());
        }
    }
}