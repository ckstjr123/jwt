package com.jwt.springsecurityjwt.constant;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Role {
    public static final String USER = "USER";
    public static final String ADMIN = "ADMIN";
}