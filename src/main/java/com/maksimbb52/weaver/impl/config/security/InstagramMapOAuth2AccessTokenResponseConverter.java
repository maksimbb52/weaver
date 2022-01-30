package com.maksimbb52.weaver.impl.config.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Map;

public class InstagramMapOAuth2AccessTokenResponseConverter
        implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {

    @Override
    public OAuth2AccessTokenResponse convert(Map<String, Object> source) {
        return OAuth2AccessTokenResponse.withToken(getParameterValue(source, OAuth2ParameterNames.ACCESS_TOKEN))
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .additionalParameters(Map.of("user_id", getUserId(source)))
                .build();
    }

    private static String getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName) {
        Object obj = tokenResponseParameters.get(parameterName);
        return (obj != null) ? obj.toString() : null;
    }

    private static String getUserId(Map<String, Object> tokenResponseParameters) {
        if (tokenResponseParameters.containsKey("user_id")) {
            return getParameterValue(tokenResponseParameters, "user_id");
        } else if (tokenResponseParameters.containsKey(OAuth2ParameterNames.USERNAME)) {
            return getParameterValue(tokenResponseParameters, OAuth2ParameterNames.USERNAME);
        }
        return null;
    }
}
