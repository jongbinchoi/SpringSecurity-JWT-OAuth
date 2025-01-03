package com.example.login.service;

import com.example.login.entity.User;
import com.example.login.enums.Role;
import com.example.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();  // google, naver, kakao
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String providerId;
        String email;
        String name;

        // 🔹 각 소셜 로그인에 따라 사용자 정보 매핑
        if (provider.equals("google")) {
            providerId = (String) attributes.get("sub");
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
        } else if (provider.equals("naver")) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            providerId = (String) response.get("id");
            email = (String) response.get("email");
            name = (String) response.get("name");
        } else if (provider.equals("kakao")) {
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
            providerId = Optional.ofNullable(attributes.get("id"))
                    .map(Object::toString)
                    .orElseThrow(() -> new IllegalArgumentException("Kakao providerId is missing"));
            email = (String) kakaoAccount.get("email");
            name = (String) profile.get("nickname");
        } else {
            throw new IllegalArgumentException("지원되지 않은 제공자 : " + provider);
        }

        // 🔹 사용자 정보 확인 및 등록 검증
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            return oAuth2User;
        } else {
            return registerNewUser(email, name, provider, providerId, oAuth2User);
        }
    }

    // 🔹 신규 사용자 등록 (OAuth 회원가입)
    private OAuth2User registerNewUser(String email, String name, String provider, String providerId, OAuth2User oAuth2User) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(name);  // 사용자 이름
        user.setUserId(email);   // 이메일을 로그인 ID로 사용
        user.setRole(Role.ROLE_USER);  // 기본 권한
        user.setProvider(provider);  // google, naver, kakao
        user.setProviderId(providerId);  // 고유 ID

        userRepository.save(user);

        return oAuth2User;  // 기존 사용자 객체 반환
    }
}

