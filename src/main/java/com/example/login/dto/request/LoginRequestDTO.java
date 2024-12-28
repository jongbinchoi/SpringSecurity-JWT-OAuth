package com.example.login.dto.request;

import com.example.login.enums.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDTO {
    private String username;
    private String password;
    private Role role;
}