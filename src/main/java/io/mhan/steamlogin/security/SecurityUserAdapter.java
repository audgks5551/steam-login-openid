package io.mhan.steamlogin.security;

import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public interface SecurityUserAdapter extends OAuth2User {
    @Override
    default Map<String, Object> getAttributes() {
        return null;
    }
}
