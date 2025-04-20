package com.jwt.springsecurityjwt.exception;

import com.jwt.springsecurityjwt.exception.response.AuthExceptionType;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@Getter
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthenticationException extends org.springframework.security.core.AuthenticationException {

    private final AuthExceptionType authExceptionType;

    public AuthenticationException(AuthExceptionType authExceptionType) {
        super(authExceptionType.getDescription());
        this.authExceptionType = authExceptionType;
    }

    public AuthenticationException(AuthExceptionType authExceptionType, Throwable cause) {
        super(authExceptionType.getDescription(), cause);
        this.authExceptionType = authExceptionType;
    }
}
