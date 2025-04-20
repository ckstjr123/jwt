package com.jwt.springsecurityjwt.exception;


import com.jwt.springsecurityjwt.exception.response.AuthExceptionType;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class RefreshViolationException extends AuthenticationException {

    public RefreshViolationException(AuthExceptionType authExceptionType) {
        super(authExceptionType);
    }
}
