package com.maksimbb52.weaver.impl.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.StringUtils;

import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2ClientProperties oAuth2ClientProperties;

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/monitoring/**",
                "/swagger*/**",
                "/v2/api-docs");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(oAuth2UserService())
                .and()
                .tokenEndpoint()
                .accessTokenResponseClient(new InstagramAuthorizationCodeTokenResponseClient());
    }

//    @Bean
//    public ClientRegistrationRepository instagramClientRegistration() {
//        OAuth2ClientProperties.Registration instagramRegistration = oAuth2ClientProperties.getRegistration().get("instagram");
//        OAuth2ClientProperties.Provider instagramProvider = oAuth2ClientProperties.getProvider().get("instagram");
//        if (instagramProvider == null || instagramRegistration == null) {
//            throw new IllegalStateException("Instagram provider was not found in application configuration");
//        }
//
//        return ClientRegistration.withRegistrationId("instagram")
//                .providerConfigurationMetadata(instagramProvider.getConfigurationMetadata())
//                .clientId(instagramRegistration.getClientId())
//                .authorizationGrantType(new AuthorizationGrantType(instagramRegistration.getAuthorizationGrantType()))
//                .authorizationUri(instagramProvider.getAuthorizationUri())
//                .build();
//
//    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        oAuth2UserService.setRequestEntityConverter(new InstagramOAuth2UserShortRequestEntityConverter());
        return oAuth2UserService;
    }

//    private ClientRegistration googleClientRegistration() {
//	  		return ClientRegistration.withRegistrationId("google")
//                 			.clientId("google-client-id")
//                 			.clientSecret("google-client-secret")
//                 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                 			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
//                 			.scope("openid", "profile", "email", "address", "phone")
//                 			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//                 			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
//                 			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                    .providerConfigurationMetadata()
//                 			.userNameAttributeName(IdTokenClaimNames.SUB)
//                 			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
//                 			.clientName("Google")
//                 			.build();
//	 	}
}
