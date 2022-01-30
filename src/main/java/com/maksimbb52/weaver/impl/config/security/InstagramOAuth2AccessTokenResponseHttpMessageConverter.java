package com.maksimbb52.weaver.impl.config.security;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.DefaultOAuth2AccessTokenResponseMapConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponseMapConverter;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class InstagramOAuth2AccessTokenResponseHttpMessageConverter extends AbstractHttpMessageConverter<OAuth2AccessTokenResponse> {

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
    };

    private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

    private Converter<Map<String, Object>, OAuth2AccessTokenResponse> accessTokenResponseConverter = new InstagramMapOAuth2AccessTokenResponseConverter();

    private Converter<OAuth2AccessTokenResponse, Map<String, Object>> accessTokenResponseParametersConverter = new DefaultOAuth2AccessTokenResponseMapConverter();

    public InstagramOAuth2AccessTokenResponseHttpMessageConverter() {
        super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return OAuth2AccessTokenResponse.class.isAssignableFrom(clazz);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected OAuth2AccessTokenResponse readInternal(Class<? extends OAuth2AccessTokenResponse> clazz,
                                                     HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
        try {
            Map<String, Object> tokenResponseParameters = (Map<String, Object>) this.jsonMessageConverter
                    .read(STRING_OBJECT_MAP.getType(), null, inputMessage);
            return this.accessTokenResponseConverter.convert(tokenResponseParameters);
        } catch (Exception ex) {
            throw new HttpMessageNotReadableException(
                    "An error occurred reading the OAuth 2.0 Access Token Response: " + ex.getMessage(), ex,
                    inputMessage);
        }
    }

    @Override
    protected void writeInternal(OAuth2AccessTokenResponse tokenResponse, HttpOutputMessage outputMessage)
            throws HttpMessageNotWritableException {
        try {
            Map<String, Object> tokenResponseParameters;
            tokenResponseParameters = this.accessTokenResponseParametersConverter.convert(tokenResponse);
            this.jsonMessageConverter.write(tokenResponseParameters, STRING_OBJECT_MAP.getType(),
                    MediaType.APPLICATION_JSON, outputMessage);
        } catch (Exception ex) {
            throw new HttpMessageNotWritableException(
                    "An error occurred writing the Instagram OAuth 2.0 Access Token Response: " + ex.getMessage(), ex);
        }
    }

    /**
     * Sets the {@link Converter} used for converting the OAuth 2.0 Access Token Response
     * parameters to an {@link OAuth2AccessTokenResponse}.
     *
     * @param accessTokenResponseConverter the {@link Converter} used for converting to an
     *                                     {@link OAuth2AccessTokenResponse}
     * @since 5.6
     */
    public final void setAccessTokenResponseConverter(
            Converter<Map<String, Object>, OAuth2AccessTokenResponse> accessTokenResponseConverter) {
        Assert.notNull(accessTokenResponseConverter, "accessTokenResponseConverter cannot be null");
        this.accessTokenResponseConverter = accessTokenResponseConverter;
    }

    /**
     * Sets the {@link Converter} used for converting the
     * {@link OAuth2AccessTokenResponse} to a {@code Map} representation of the OAuth 2.0
     * Access Token Response parameters.
     *
     * @param accessTokenResponseParametersConverter the {@link Converter} used for
     *                                               converting to a {@code Map} representation of the Access Token Response parameters
     * @since 5.6
     */
    public final void setAccessTokenResponseParametersConverter(
            Converter<OAuth2AccessTokenResponse, Map<String, Object>> accessTokenResponseParametersConverter) {
        Assert.notNull(accessTokenResponseParametersConverter, "accessTokenResponseParametersConverter cannot be null");
        this.accessTokenResponseParametersConverter = accessTokenResponseParametersConverter;
    }

    static class HttpMessageConverters {

        private static final boolean jackson2Present;

        private static final boolean gsonPresent;

        private static final boolean jsonbPresent;

        static {
            ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
            jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
                    && ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
            gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
            jsonbPresent = ClassUtils.isPresent("javax.json.bind.Jsonb", classLoader);
        }

        private HttpMessageConverters() {
        }

        static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
            if (jackson2Present) {
                return new MappingJackson2HttpMessageConverter();
            }
            if (gsonPresent) {
                return new GsonHttpMessageConverter();
            }
            if (jsonbPresent) {
                return new JsonbHttpMessageConverter();
            }
            return null;
        }
    }
}
