package com.example.login.service;

import com.example.login.enums.Role;
import com.example.login.entity.User;
import com.example.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;



    // 사용자 인증 (로그인 검증)
    public User authenticate(String username, String password) {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isPresent() && user.get().getPassword().equals(password)) {
            return user.get();
        }
        return null;
    }

    // 회원가입 로직
    public User register(String username, String password) {
        // 사용자 중복 체크
        Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            throw new RuntimeException("이미 존재하는 사용자입니다.");
        }

        // 사용자 정보 저장 (비밀번호 암호화)
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));  // 비밀번호 암호화
        user.setRole(Role.ROLE_USER);  // 기본 권한 부여
        return userRepository.save(user);
    }


    // 사용자 ID로 사용자 조회 (getUserById 메서드 추가)
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
    }

}
