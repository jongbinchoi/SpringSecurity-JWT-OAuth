package com.example.login;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    // 특정 역할의 사용자 조회 예시
    Optional<User> findByRole(Role role);
}
