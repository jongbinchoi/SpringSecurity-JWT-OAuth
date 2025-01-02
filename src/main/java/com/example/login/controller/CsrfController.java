package com.example.login.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {

    @GetMapping("/api/csrf")
    public CsrfToken csrf(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }

    //todo HttpServletRequest 는 사용자가  서버로 보낸 HTTP 요청 정보를 담는 객체
    // request.getAttribute(...) -> 요청에 정장된 속성 을 가져온느 메서드
    // CsrfToken.class.getName() -> 요청에 저장된 CSRF 토큰을 꺼낼 때 사용하는 키
}
