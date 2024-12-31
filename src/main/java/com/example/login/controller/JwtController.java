package com.example.login.controller;

import com.example.login.JWT.JwtUtil;
import com.example.login.dto.request.LoginRequestDTO;
import com.example.login.dto.request.RegisterRequestDTO;
import com.example.login.entity.User;
import com.example.login.service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtController {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final CsrfTokenRepository csrfTokenRepository;

    // 리프레시 토큰을 사용해 새 액세스 토큰 발급
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) { //클라이언트 요청과 서버 응답을 다루는 객체
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("쿠키 찾을 수 없음");
        }

        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token 찾을 수 없음");
        }

        try {
            Claims claims = jwtUtil.getUserIdFromToken(refreshToken); // 사용자 정보 검증
            Long userId = Long.valueOf(claims.getSubject());

            // 새 액세스 토큰 발급
            String newAccessToken = jwtUtil.generateAccessToken(userId);

            // 리프레시 토큰 만료 임박 시 새로 발급
            Date expiration = claims.getExpiration(); //리프레시 토큰의 만료 시간을 가져옴
            long now = System.currentTimeMillis();
            long timeUntilExpiration = expiration.getTime() - now; //현재시간과 만료시간 비교해 남은 시간 계산

            String newRefreshToken = refreshToken;
            if (timeUntilExpiration < (3 * 24 * 60 * 60 * 1000)) {  // 3일 이하 남았을 경우 갱신
                newRefreshToken = jwtUtil.generateRefreshToken(userId);

                // 새 리프레시 토큰을 쿠키에 저장
                //todo HttpOnly쿠키 : 자바스크립트에서 접근 할 수 없도록 설정 -> XSS 공격 방지
                Cookie refreshCookie = new Cookie("refreshToken", newRefreshToken); //이름, 값 = refreshToken에 newRefreshToken 값을 담아
                refreshCookie.setHttpOnly(true);
                refreshCookie.setSecure(true); //HTTPS 환경에서만 쿠키를 전송
                refreshCookie.setPath("/api/auth/refresh"); //이 쿠키는 여기서만 접근가능
                refreshCookie.setMaxAge(7 * 24 * 60 * 60);  // 7일
                refreshCookie.setAttribute("SameSite", "Strict"); // CSRF 공격방어, 다른 사이트에서 요청할 경우 쿠키를 전송하지 않도록 설정
                response.addCookie(refreshCookie);
            }

            return ResponseEntity.ok().body(Map.of("accessToken", newAccessToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Refresh Token 유효하지않음");
        }
    }

    //todo 리프레시 토큰 = 쿠키, 액세스토큰=JSON

    // 로그인 (액세스 토큰 + 리프레시 토큰 발급)
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginRequestDTO,  HttpServletRequest request, HttpServletResponse response) {
        log.info("로그인 시도 - 사용자명: {}", loginRequestDTO.getUsername());
        User user = userService.authenticate(loginRequestDTO.getUsername(), loginRequestDTO.getPassword());

        if (user == null) {
            log.warn("로그인 실패 - 사용자명: {}",loginRequestDTO.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // 액세스 토큰과 리프레시 토큰 발급
        String accessToken = jwtUtil.generateAccessToken(user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        log.info("로그인 성공 - 사용자 ID: {}, Access Token: {}, Refresh Token: {}", user.getId(), accessToken, refreshToken);

        // 리프레시 토큰을 HttpOnly 쿠키에 저장
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false);  // 개발 환경에서는 false로 설정
        refreshCookie.setPath("/"); // 모든 경로에서 쿠키 사용 가능
        refreshCookie.setMaxAge(7 * 24 * 60 * 60);  // 7일
        refreshCookie.setAttribute("SameSite", "Strict");

        response.addCookie(refreshCookie);

        return ResponseEntity.ok().body(Map.of(
                "accessToken", accessToken
        ));

    }

    //회원가입
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequestDTO request) {
        log.info("회원가입 시도 - 사용자명: {}", request.getUsername());

        try {
            userService.register(request.getUsername(), request.getPassword());
            log.info("회원가입 성공 - 사용자명: {}", request.getUsername());
            return ResponseEntity.ok("회원가입 성공");
        } catch (Exception e) {
            log.error("회원가입 실패 - 사용자명: {}, 이유: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

}
