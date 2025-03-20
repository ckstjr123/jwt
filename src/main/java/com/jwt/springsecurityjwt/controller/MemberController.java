package com.jwt.springsecurityjwt.controller;

import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
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
}
