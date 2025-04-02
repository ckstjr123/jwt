package com.jwt.springsecurityjwt.jwt.vo;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public final class JwtReissueRequest {
    private final String refreshToken;
}
