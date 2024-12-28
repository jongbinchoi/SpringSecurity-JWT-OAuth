package com.example.login.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    //자동으로 안전한 키 생성
    private Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); /// HMAC-SHA 256에 맞는 키 자동 생성

    private static final long ACCESS_EXPIRATION = 1000 * 60 * 60;  // 1시간
    private static final long REFRESH_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7일 (리프레시 토큰)

    // 액세스 토큰 생성
    public String generateAccessToken(Long userId) {
        String token = Jwts.builder()
                .setSubject(String.valueOf(userId)) //사용자 식별 정보를 토큰에 담음, 일반 적으로 username, email, userId 식별자 사용, JWT의 subject(주체)는 String 타입으로 저장
                .setIssuedAt(new Date()) //토큰 발급시간
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION))
                .signWith(key)  // key만 전달 (HS256 기본 설정), 서명
                .compact(); //최종적으로 JWT 문자열 반환
        return "Bearer " + token;
    }

    public String generateRefreshToken(Long userId) {
        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION))
                .signWith(key)
                .compact();
    }


    // 토큰에서 사용자 정보 추출
    public Claims getUserIdFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    //todo 왜 한번에 안하고 build()를 따로 호출? => 유연성을 높이기 위함, 예를 들어 , setSigningKey  외에도 옵션 추가가능
    //    .requireIssuer("myapp")  // 발급자(issuer) 검증 추가
    //    .requireAudience("user")  // 특정 audience만 허용 => 추가적인 검증 조건 붙일 수있다

    // 리프레시 토큰 검증 및 재발급
    public String refreshAccessToken(String refreshToken) {
        try {
            //claims은 사용자정보(페이로드)를 뜻함
            //Jwts.parserBuilder()는 JWT를 해석하고 검증하는 도구
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // 서명 검증을 위한 동일 키로 검증
                    .build()
                    .parseClaimsJws(refreshToken)//JWT 파싱(해석) 및 검증 , 유효하지 않을 때 jwtException으로 던짐
                    .getBody();//JWT의 데이터를 반환 페이로드

            Long userId = Long.valueOf(claims.getSubject());
            return generateAccessToken(userId);  // 새 액세스 토큰 발급
        } catch (Exception e) {
            throw new RuntimeException("유효하지 않은 리프레쉬 토큰");
        }

    }
}