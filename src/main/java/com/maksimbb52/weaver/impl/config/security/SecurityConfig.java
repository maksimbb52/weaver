package com.maksimbb52.weaver.impl.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;

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
                .oauth2Client(oauth2 -> oauth2
                        .clientRegistrationRepository(instagramClientRegistration())
                        .authorizationCodeGrant()
                        .accessTokenResponseClient(new InstagramAuthorizationCodeTokenResponseClient())
                )
//                .oauth2Login(oauth2 -> oauth2
//                        .clientRegistrationRepository(instagramClientRegistration())
//                        .userInfoEndpoint()
//                        .userService(oAuth2UserService())
//                        .and()
//                        .tokenEndpoint()
//                        .accessTokenResponseClient(new InstagramAuthorizationCodeTokenResponseClient())
//                )
        ;
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient = new Defa`ultRefreshTokenTokenResponseClient();
        //TODO set converters

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken(configurer -> configurer.accessTokenResponseClient(refreshTokenTokenResponseClient))
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    private ClientRegistrationRepository instagramClientRegistration() {
        OAuth2ClientProperties.Registration instagramRegistration = oAuth2ClientProperties.getRegistration().get("instagram");
        OAuth2ClientProperties.Provider instagramProvider = oAuth2ClientProperties.getProvider().get("instagram");
        if (instagramProvider == null || instagramRegistration == null) {
            throw new IllegalStateException("Instagram provider was not found in application configuration");
        }

        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("instagram")
                .providerConfigurationMetadata(instagramProvider.getConfigurationMetadata())
                .clientId(instagramRegistration.getClientId())
                .authorizationGrantType(new AuthorizationGrantType(instagramRegistration.getAuthorizationGrantType()))
                .authorizationUri(instagramProvider.getAuthorizationUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(instagramRegistration.getClientAuthenticationMethod()))
                .clientSecret(instagramRegistration.getClientSecret())
                .clientName(instagramRegistration.getClientName())
                .redirectUri(instagramRegistration.getRedirectUri())
                .scope(instagramRegistration.getScope())
                .tokenUri(instagramProvider.getTokenUri())
                .userInfoAuthenticationMethod(new AuthenticationMethod(instagramProvider.getUserInfoAuthenticationMethod()))
                .userInfoUri(instagramProvider.getUserInfoUri())
                .userNameAttributeName(instagramProvider.getUserNameAttribute())
                .build());

    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        oAuth2UserService.setRequestEntityConverter(new InstagramOAuth2UserRequestEntityConverter());
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
