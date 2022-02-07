package com.maksimbb52.weaver.impl.config.security;

import lombok.*;

@Value
@Builder(toBuilder = true)
public class InstagramExchangeTokenResponse {

    String accessToken;
    String tokenType;
    /** seconds left to expiration */
    Long expiresIn;
}
