package com.example.login.dto.request;

import com.example.login.enums.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDTO {
    private String userId;
    private String password;
    private Role role;
}
