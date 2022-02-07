package com.maksimbb52.weaver.impl.config.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Map;
import java.util.Optional;

public class InstagramMapExchangeTokenResponseConverter
        implements Converter<Map<String, Object>, InstagramExchangeTokenResponse> {

    @Override
    public InstagramExchangeTokenResponse convert(Map<String, Object> source) {
        return InstagramExchangeTokenResponse.builder()
                .accessToken(getParameterValue(source, OAuth2ParameterNames.ACCESS_TOKEN))
                .tokenType(getParameterValue(source, OAuth2ParameterNames.TOKEN_TYPE))
                .expiresIn(Optional.ofNullable(getParameterValue(source, OAuth2ParameterNames.EXPIRES_IN))
                        .map(Long::parseLong)
                        .orElse(5100836L))
                .build();
    }

    private static String getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName) {
        Object obj = tokenResponseParameters.get(parameterName);
        return (obj != null) ? obj.toString() : null;
    }
}
