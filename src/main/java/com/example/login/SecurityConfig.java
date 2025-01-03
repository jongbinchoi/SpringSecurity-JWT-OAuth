package com.example.login;

import com.example.login.JWT.JwtTokenFilter;
import com.example.login.JWT.JwtUtil;
import com.example.login.repository.UserRepository;
import com.example.login.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


    private final JwtTokenFilter jwtTokenFilter;


    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_OWNER \n ROLE_owner > ROLE_USER");
        return roleHierarchy;
    }



    // SecurityFilterChain – Spring Security 필터 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  // CSRF 토큰 발급 및 쿠키 저장
                        .ignoringRequestMatchers("/h2-console/**")  // H2 콘솔 CSRF 비활성화

                )
                .formLogin(formLogin -> formLogin.disable()) // 폼 로그인 비활성화
                .httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 인증 비활성화
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable())) // X-Frame-Options 비활성화

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/*", "/api/auth/refresh", "/h2-console/**","/api/*","/user/**").permitAll()  // 로그인, 리프레시 허용
                        .anyRequest().authenticated()  // 나머지 API는 인증 필요
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/user/info", true) // 로그인 성공 후 이동 경로
                        .failureUrl("/login?error=true") // 로그인 실패 시
                )

                //todo 요청이 API로 전달 되기전 검증 해야함, SecurityFilterChain보다 먼저 실행, 헤더에서 JWT추출하고 검증역할
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);  // JWT 필터 추가, 로그인 요청을 처리하는 필터



        return http.build();
    }

    // 인증 매니저 설정 (비밀번호 검증 등)
    //AuthenticationManager는 사용자의 아이디와 비밀번호를 검증하는 역할
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // 비밀번호 암호화
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*"); // 모든 도메인 허용 (Spring Boot 2.4+)
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true); // 자격 증명 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    //todo 기본적으로 Spring Security는 HTML폼 기반 CSRF보호함 -> 따로 커스텀 CSRF토큰 저장소 설정해야지, REST API, AJAX 요청 또는 다른 HTTP 메서드도 CSRF 보호를 적용
    //      REST API에서는 CSRF 토큰을 쿠키에 저장하고, 클라이언트가 이를 헤더에 추가하는 방식이 필요
    //      CookieCsrfTokenRepository는 이 과정을 자동으로 처리
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
        repository.setCookieHttpOnly(false);  // JavaScript에서 접근 가능하게 설정 (클라이언트가 읽어야 함)
        repository.setHeaderName("X-XSRF-TOKEN");  // CSRF 토큰을 포함하는 헤더 이름
        repository.setCookieName("XSRF-TOKEN");  // CSRF 토큰 쿠키 이름
        return repository;
    }


}
