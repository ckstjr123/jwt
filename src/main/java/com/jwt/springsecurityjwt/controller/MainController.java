package com.jwt.springsecurityjwt.controller;

import com.jwt.springsecurityjwt.jwt.JwtUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class MainController {

    @GetMapping("/")
    public String main(@AuthenticationPrincipal JwtUser loginMember) {
        if (loginMember != null) {
            log.info("login member id: {}", loginMember.getMemberId());
        }

        return "Main Controller";
    }
}
