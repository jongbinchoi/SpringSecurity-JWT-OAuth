package com.example.login.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class loginInfo {

    @GetMapping("/")
    public String home() {
        return "login";
    }



    @GetMapping("/user/info")
    public String info() {
        return "userInfo";
    }
}
