package com.example.login.dto.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequestDTO {
    private String userId;
    private String username;
    private String password;
    private String email;
}
