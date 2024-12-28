package com.example.login;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtController {

    private final JwtUtil jwtUtil;

    //리프레시 토큰을 사용해 새 액세스 토큰 발급
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No cookies found");
        }

        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token not found");
        }

        try {
            Claims claims = jwtUtil.getUserIdFromToken(refreshToken);
            Long userId = Long.valueOf(claims.getSubject());

            // 새 액세스 토큰 발급
            String newAccessToken = jwtUtil.generateAccessToken(userId);

            // 리프레시 토큰 만료 임박 시 새로 발급
            Date expiration = claims.getExpiration();
            long now = System.currentTimeMillis();
            long timeUntilExpiration = expiration.getTime() - now;

            String newRefreshToken = refreshToken;
            if (timeUntilExpiration < (3 * 24 * 60 * 60 * 1000)) {
                newRefreshToken = jwtUtil.generateRefreshToken(userId);

                Cookie refreshCookie = new Cookie("refreshToken", newRefreshToken);
                refreshCookie.setHttpOnly(true);
                refreshCookie.setSecure(true);
                refreshCookie.setPath("/api/auth/refresh");
                refreshCookie.setMaxAge(7 * 24 * 60 * 60);
                refreshCookie.setAttribute("SameSite", "Strict");
                response.addCookie(refreshCookie);
            }

            return ResponseEntity.ok().body(Map.of("accessToken", newAccessToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid Refresh Token");
        }
}
