package com.example.login.service;

import org.springframework.core.env.Environment;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

@Service
public class DebugService {

    private final Environment environment;

    public DebugService(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    public void init() {
        System.out.println("Active Profiles: " + String.join(", ", environment.getActiveProfiles()));
        System.out.println("Google Client-secret: " + environment.getProperty("secrets.oauth.google.client-secret"));
        System.out.println("Google Client ID: " + environment.getProperty("secrets.oauth.google.client-id"));
        System.out.println("naver Client-secret: " + environment.getProperty("secrets.oauth.naver.client-secret"));
        System.out.println("naver Client ID: " + environment.getProperty("secrets.oauth.naver.client-id"));
        System.out.println("OAuth Kakao Provider: " + environment.getProperty("spring.security.oauth2.client.provider.kakao.authorization-uri"));
        System.out.println("kakao Client-secret: " + environment.getProperty("secrets.oauth.kakao.client-secret"));
        System.out.println("kakao Client ID: " + environment.getProperty("secrets.oauth.kakao.client-id"));
    }
}
