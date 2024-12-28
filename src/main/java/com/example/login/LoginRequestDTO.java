package com.example.login;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDTO {
    private String username;
    private String password;
    private Role role;
}
