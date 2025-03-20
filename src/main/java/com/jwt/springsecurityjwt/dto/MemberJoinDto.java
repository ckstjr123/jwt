package com.jwt.springsecurityjwt.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberJoinDto {
    private String username;
    private String password;
}
