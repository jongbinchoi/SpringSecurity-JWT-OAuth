package com.example.login;

import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // 사용자 인증 (로그인 검증)
    public User authenticate(String username, String password) {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isPresent() && user.get().getPassword().equals(password)) {
            return user.get();
        }
        return null;
    }

    // 사용자 회원가입 (기본 ROLE_USER 부여)
    public User register(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setRole(Role.ROLE_USER);  // 기본 역할 USER로 설정
        return userRepository.save(user);
    }
}
