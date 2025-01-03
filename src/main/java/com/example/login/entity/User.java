package com.example.login.entity;

import com.example.login.enums.Role;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    @Column(unique = true)
    private String userId; //로그인 아이디

    @Column(unique = false)
    private String username;

    private String password;

    @Enumerated(EnumType.STRING)  // DB에 저장할 때 Enum의 이름 그대로 저장
    private Role role;  // Enum 타입으로 변경

    private String provider;  // 구글, 네이버, 카카오 구분 (GOOGLE, NAVER, KAKAO)
    private String providerId;  // 소셜 로그인에서 제공하는 고유 ID


    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }
}
