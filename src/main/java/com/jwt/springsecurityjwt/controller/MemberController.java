package com.jwt.springsecurityjwt.controller;

import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.exception.RefreshViolationException;
import com.jwt.springsecurityjwt.jwt.vo.JwtReissueRequest;
import com.jwt.springsecurityjwt.jwt.vo.JwtResponse;
import com.jwt.springsecurityjwt.service.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public void reissue(@CookieValue("refreshToken") String refreshToken, HttpServletRequest request, HttpServletResponse response) {
        try {
            JwtResponse tokenResponse = this.memberService.refresh(new JwtReissueRequest(refreshToken));
            response.setHeader(HttpHeaders.AUTHORIZATION, tokenResponse.getAccessToken());
            response.addCookie(new Cookie("refreshToken", tokenResponse.getRefreshToken()));
        } catch (RefreshViolationException ex) {
            new CookieClearingLogoutHandler("refreshToken").logout(request, response, null);
        }
    }
}
