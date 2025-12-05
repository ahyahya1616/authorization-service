package ma.fstt.authservice.security;

import ma.fstt.authservice.model.UserDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public class MetamaskUserPrincipal implements Authentication {

    private final UserDto user;
    private final Collection<? extends GrantedAuthority> authorities;
    private boolean authenticated = true;

    public MetamaskUserPrincipal(UserDto user) {
        this.user = user;
        this.authorities = List.of(new SimpleGrantedAuthority(user.role()));
    }

    public UserDto getUser() {
        return user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null; // pas utilisé ici
    }

    @Override
    public Object getDetails() {
        return null; // optionnel
    }

    @Override
    public Object getPrincipal() {
        return this; // ou user si tu préfères
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return user.wallet(); // utiliser le wallet comme nom
    }
}
