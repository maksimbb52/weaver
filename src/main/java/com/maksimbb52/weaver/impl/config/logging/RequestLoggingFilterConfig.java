package com.maksimbb52.weaver.impl.config.logging;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.ServletContextRequestLoggingFilter;

import javax.servlet.http.HttpServletRequest;

@Configuration
public class RequestLoggingFilterConfig {

    @Bean
    public CustomRequestLoggingFilter logFilter() {
        var filter = new CustomRequestLoggingFilter();
        filter.setIncludeQueryString(true);
        filter.setIncludePayload(true);
        filter.setMaxPayloadLength(10000);
        filter.setIncludeHeaders(false);
        filter.setAfterMessagePrefix("REQUEST  : ");

        return filter;
    }

    @Slf4j
    public static class CustomRequestLoggingFilter extends ServletContextRequestLoggingFilter {
        @Override
        protected boolean shouldLog(HttpServletRequest request) {
            return !request.getServletPath().contains("actuator")
                    && !request.getServletPath().contains("swagger") ;
        }
    }
}