package com.maksimbb52.weaver.impl.config.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

public class InstagramOAuth2ExchangeTokenGrantRequestEntityConverter {

    private static final String ATT_GRANT_TYPE = "grant-type";
    private static final String ATT_LONG_LIVED_TOKEN_URI = "long-lived-token-uri";

    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest requestModel, String shortLivedAccessToken) {
        ClientRegistration clientRegistration = requestModel.getClientRegistration();
        HttpMethod httpMethod = HttpMethod.GET;
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        Map<String, Object> configurationMetadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
        URI uri = UriComponentsBuilder
                .fromUriString(configurationMetadata.get(ATT_LONG_LIVED_TOKEN_URI).toString())
                .queryParam(OAuth2ParameterNames.GRANT_TYPE, configurationMetadata.get(ATT_GRANT_TYPE))
                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret())
                .queryParam(OAuth2ParameterNames.ACCESS_TOKEN, shortLivedAccessToken)
                .build()
                .toUri();

        headers.setBearerAuth(shortLivedAccessToken);

        return new RequestEntity<>(headers, httpMethod, uri);
    }
}
