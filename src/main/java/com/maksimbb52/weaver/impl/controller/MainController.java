package com.maksimbb52.weaver.impl.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

//    @GetMapping("/hello")
//    public String hello(@AuthenticationPrincipal OAuth2User principal) {
//        return null;
//    }

    @GetMapping("/hello")
    public String hello(@RegisteredOAuth2AuthorizedClient("instagram") OAuth2AuthorizedClient authorizedClient) {
        return null;
    }
}
