package com.example.login.repository;

import com.example.login.enums.Role;
import com.example.login.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    // 특정 역할의 사용자 조회 예시
    Optional<User> findByRole(Role role);
}
