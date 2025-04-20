package com.jwt.springsecurityjwt.exception.response;

import lombok.Getter;

@Getter
public enum AuthExceptionType implements ExceptionType {

    //JWT 인증 관련 예외 타입
    SIGNATURE_JWT("시그니처 검증에 실패한 JWT 토큰입니다."),
    EXPIRED_JWT("만료된 JWT 토큰입니다."),
    MALFORMED_JWT("손상된 토큰입니다."),
    UNSUPPORTED_JWT("지원하지 않는 JWT 토큰입니다."),
    INVALID_JWT("유효하지 않은 JWT 토큰입니다."),
    VIOLATE_REFRESH_JWT("비정상적인 JWT 갱신 토큰 사용이 감지되었습니다.");

    private final String errorCode;
    private final String description;

    AuthExceptionType(String description) {
        this.errorCode = this.name();
        this.description = description;
    }
}
