package com.example.login;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@RequiredArgsConstructor
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, //클라이언트의 요청 정보
                                    HttpServletResponse response, //클라이언로 보낼 응답
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization"); //JWT는 헤더에 담겨 전송

        if (authHeader != null && authHeader.startsWith("Bearer ")) { //null아니고 접두사가 있을 경우 7번재 문자 부터 토큰 추출
            String token = authHeader.substring(7);

            try {
                Long userId = jwtUtil.getUserIdFromToken(token).get("userId", Long.class); // clamins에서 값을 꺼낼때 명시적으로 타입을 지정해야함, 하지않으면 object 로 변환 형변환 필요
                User user = userService.getUserById(userId);

                //UsernamePasswordAuthenticationToken = 인증된 사용자 정보를 담는 객체, 인증배지 같은것
                //todo API 요청이 들어올 때, JWT(토큰)를 분석해 사용자 정보를 확인
                //      인증된 사용자를 스프링 시큐리티에서 관리
                //      UsernamePasswordAuthenticationToken을 사용해 => "이 사용자는 인증된 사용자입니다"**라고 알려줌

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(user, null, null); //null, null은 비밀번호와 권한 생략
                SecurityContextHolder.getContext().setAuthentication(authentication); //SecurityContext는 인증 정보를 저장하는 곳

            } catch (Exception e) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}
