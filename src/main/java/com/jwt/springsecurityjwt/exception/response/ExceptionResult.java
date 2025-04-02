package com.jwt.springsecurityjwt.exception.response;

import lombok.Getter;

@Getter
public class ExceptionResult {

    private final String errorCode;
    private final String message;

    private ExceptionResult(String errorCode, String message) {
        this.errorCode = errorCode;
        this.message = message;
    }

    public static ExceptionResult from(ExceptionType exceptionType) {
        return new ExceptionResult(exceptionType.getErrorCode(), exceptionType.getDescription());
    }
}
