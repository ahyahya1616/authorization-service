package ma.fstt.authservice.controller;

import feign.FeignException;
import jakarta.validation.Valid;
import ma.fstt.authservice.dto.MetamaskLoginRequest;
import ma.fstt.authservice.dto.TokenResponse;
import ma.fstt.authservice.service.MetamaskTokenService;
import ma.fstt.authservice.service.NonceService;
import ma.fstt.authservice.service.SignatureVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Contrôleur pour l'authentification MetaMask
 * Ces endpoints sont appelés par le Gateway
 */
@RestController
@RequestMapping("/api/auth/metamask")
public class MetamaskAuthController {

    private static final Logger log = LoggerFactory.getLogger(MetamaskAuthController.class);

    private final SignatureVerificationService signatureService;
    private final MetamaskTokenService tokenService;
    private final NonceService nonceService ;

    public MetamaskAuthController(
            SignatureVerificationService signatureService,
            MetamaskTokenService tokenService,
            NonceService nonceService) {
        this.signatureService = signatureService;
        this.tokenService = tokenService;
        this.nonceService = nonceService;
    }

    /**
     * GET /api/auth/metamask/nonce?wallet=0x123...
     * Génère un nonce pour la signature
     */
    @GetMapping("/nonce")
    public ResponseEntity<Map<String, String>> getNonce(@RequestParam String wallet) {
        // Exception Feign NotFound ou autres sont gérées par GlobalExceptionHandler
        String nonce = nonceService.generateAndStoreNonce(wallet);
        return ResponseEntity.ok(Map.of("nonce", nonce));
    }

    /**
     * POST /api/auth/metamask/login
     * Body: { "wallet": "0x123...", "signature": "0xabc..." }
     *
     * 1. Vérifie la signature
     * 2. Génère les tokens OAuth2 directement
     * 3. Retourne les tokens au Gateway
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody MetamaskLoginRequest request) {
        log.info("🔐 Tentative de login pour wallet: {}", request.wallet());

        // La vérification de la signature lance InvalidSignatureException si problème
        signatureService.verifySignature(request.wallet(), request.signature());

        TokenResponse tokens = tokenService.generateTokens(request.wallet(), request.signature());
        log.info("✅ Tokens générés avec succès pour wallet: {}", request.wallet());

        return ResponseEntity.ok(tokens);
    }

    /**
     * POST /api/auth/metamask/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestParam("refreshToken") String refreshToken) {
        TokenResponse tokens = tokenService.refreshTokens(refreshToken);
        log.info("Tokens rafraîchis avec succès");
        return ResponseEntity.ok(tokens);
    }
}