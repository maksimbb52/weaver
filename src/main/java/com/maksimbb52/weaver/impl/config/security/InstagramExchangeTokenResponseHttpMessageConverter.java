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
import org.springframework.util.ClassUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class InstagramExchangeTokenResponseHttpMessageConverter extends AbstractHttpMessageConverter<InstagramExchangeTokenResponse> {

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
    };

    private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

    private final Converter<Map<String, Object>, InstagramExchangeTokenResponse> accessTokenResponseConverter = new InstagramMapExchangeTokenResponseConverter();

    public InstagramExchangeTokenResponseHttpMessageConverter() {
        super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return InstagramExchangeTokenResponse.class.isAssignableFrom(clazz);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected InstagramExchangeTokenResponse readInternal(Class<? extends InstagramExchangeTokenResponse> clazz,
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
    protected void writeInternal(InstagramExchangeTokenResponse tokenResponse, HttpOutputMessage outputMessage)
            throws HttpMessageNotWritableException {
        throw new UnsupportedOperationException("Write InstagramExchangeToken as String operation is not implemented");
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
