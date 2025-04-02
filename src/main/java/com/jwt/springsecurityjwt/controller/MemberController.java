package com.jwt.springsecurityjwt.controller;

import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.jwt.vo.JwtReissueRequest;
import com.jwt.springsecurityjwt.jwt.vo.JwtResponse;
import com.jwt.springsecurityjwt.service.MemberService;
import io.jsonwebtoken.Jwt;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/join")
    public String joinProcess(@ModelAttribute MemberJoinDto memberJoinDto) {
        this.memberService.join(memberJoinDto);
        return "ok";
    }

    //reissue access token
    @PostMapping("/refresh")
    public void reissue(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        JwtResponse tokenResponse = this.memberService.refresh(new JwtReissueRequest(refreshToken));
        response.setHeader(HttpHeaders.AUTHORIZATION, tokenResponse.getAccessToken());
        response.addCookie(new Cookie("refreshToken", tokenResponse.getRefreshToken()));
    }
}
