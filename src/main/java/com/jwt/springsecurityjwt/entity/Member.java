package com.jwt.springsecurityjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;

@Entity
@Getter
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    private String role;

    private String refreshToken;
    private String refreshTokenExp;

    public static Member createMember(String username, String password, String role) {
        Member member = new Member();
        member.username = username;
        member.password = password;
        member.role = role;

        return member;
    }
}
