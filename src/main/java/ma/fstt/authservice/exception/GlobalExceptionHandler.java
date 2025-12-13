package ma.fstt.authservice.exception;

import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ------------------------------------------------------------------------
    // DEPENDANCES (User-Management via OpenFeign)
    // ------------------------------------------------------------------------

    @ExceptionHandler(FeignException.class)
    public ResponseEntity<Object> handleFeignException(FeignException ex) {

        // 1️⃣ Erreur technique distante → on MASQUE
        if (ex.status() >= 500 || ex.status() == -1) {
            log.error(
                    "Erreur critique User-Service [status={}]: {}",
                    ex.status(),
                    ex.getMessage()
            );

            return buildErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "DEPENDENCY_ERROR",
                    "Service utilisateur temporairement indisponible"
            );
        }

        // 2️⃣ Erreur métier distante → PASS-THROUGH contrôlé
        String responseBody = ex.contentUTF8();

        if (responseBody == null || responseBody.isBlank()) {
            return buildErrorResponse(
                    HttpStatus.valueOf(ex.status()),
                    "REMOTE_ERROR",
                    "Erreur distante sans corps"
            );
        }

        return ResponseEntity.status(ex.status())
                .contentType(MediaType.APPLICATION_JSON)
                .body(responseBody);
    }

    // ------------------------------------------------------------------------
    // ERREURS LOCALES (Auth-Service)
    // ------------------------------------------------------------------------

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthentication(AuthenticationException ex) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "AUTHENTICATION_FAILED",
                ex.getMessage()
        );
    }

    @ExceptionHandler(InvalidSignatureException.class)
    public ResponseEntity<Object> handleInvalidSignature(InvalidSignatureException ex) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "INVALID_SIGNATURE",
                ex.getMessage()
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleValidation(MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );

        Map<String, Object> response = new HashMap<>();
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "VALIDATION_ERROR");
        response.put("message", "Requête invalide");
        response.put("details", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // ------------------------------------------------------------------------
    // FALLBACK GLOBAL
    // ------------------------------------------------------------------------

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGeneric(Exception ex) {
        log.error("Erreur inattendue Auth-Service", ex);

        return buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Erreur interne"
        );
    }

    // ------------------------------------------------------------------------
    // OUTIL DE CONSTRUCTION
    // ------------------------------------------------------------------------

    private ResponseEntity<Object> buildErrorResponse(
            HttpStatus status,
            String error,
            String message
    ) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status.value());
        response.put("error", error);
        response.put("message", message);

        return ResponseEntity.status(status).body(response);
    }
}
