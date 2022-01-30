package com.maksimbb52.weaver.impl.config.security;

import lombok.Getter;
import lombok.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.data.util.Pair;

import java.util.Map;

@Getter
@ConstructorBinding
@ConfigurationProperties(prefix = "weaver.security.oauth2.client")
public class OAuth2ClientProperties {

    Map<String, Registration> registration;
    Map<String, Provider> provider;

    @Value
    @ConstructorBinding
    static class Registration {

        String provider;
        String clientName;
        String clientId;
        String clientSecret;
        String redirectUri;
        String authorizationGrantType;
        String clientAuthenticationMethod;
        String scope;
    }

    @Value
    @ConstructorBinding
    static class Provider {

        String authorizationUri;
        String tokenUri;
        String userInfoUri;
        Map<String, Object> configurationMetadata;
        String userInfoAuthenticationMethod;
        String userNameAttribute;
    }
}
