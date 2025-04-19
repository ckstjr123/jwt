package com.jwt.springsecurityjwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.springsecurityjwt.exception.response.ExceptionResult;
import com.jwt.springsecurityjwt.exception.response.ExceptionType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        ExceptionType exceptionType = (ExceptionType) request.getAttribute(JwtProvider.JWT_EXCEPTION_ATTRIBUTE);
        if (exceptionType != null) {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            this.objectMapper.writeValue(response.getWriter(), ExceptionResult.from(exceptionType));
        }
    }
}
