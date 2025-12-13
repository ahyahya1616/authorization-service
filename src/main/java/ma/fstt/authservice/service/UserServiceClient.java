package ma.fstt.authservice.service;

import ma.fstt.authservice.model.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

/**
 * Feign Client pour communiquer avec UserManagementService
 */
@FeignClient(name = "user-management-service",  url = "${user.uri}", path = "/api/users")
public interface UserServiceClient {

    @GetMapping("/wallet/{wallet}")
    UserDto getUserByWallet(@PathVariable String wallet);

    @PostMapping("/nonce")
    void storeNonce(@RequestParam String wallet, @RequestParam String nonce);

    @GetMapping("/nonce")
    String getNonce(@RequestParam String wallet);

    @DeleteMapping("/nonce")
    void deleteNonce(@RequestParam String wallet);


}