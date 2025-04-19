package com.jwt.springsecurityjwt.jwt;

import com.jwt.springsecurityjwt.exception.AuthenticationException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.PatternMatchUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

//요청에 대해서 단 한번만 호출되는 OncePerRequestFilter 상속
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final String[] exceptURIs = {"/join", "/login", "/refresh", "/logout"};
    private final JwtProvider jwtProvider;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return PatternMatchUtils.simpleMatch(this.exceptURIs, request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.replace("Bearer ", "");

            try {
                //검증 완료된 액세스 토큰으로부터 클레임 추출
                Claims claims = this.jwtProvider.extractVaildClaims(accessToken);

                //임시 세션 보관용 유저 객체 생성
                JwtUser loginMember = JwtUser.from(claims);

                Authentication authentication = new UsernamePasswordAuthenticationToken(loginMember, null, List.of(new SimpleGrantedAuthority(loginMember.getRole())));
                SecurityContextHolder.getContext().setAuthentication(authentication); // 인증된 유저에 대해 현재 요청 동안에만 사용될 임시 세션
                log.info("{}'s JWT verification is successful", loginMember.getUsername());
            } catch (AuthenticationException ex) {
                request.setAttribute(JwtProvider.JWT_EXCEPTION_ATTRIBUTE, ex.getAuthExceptionType()); // AuthenticationEntryPoint에서 처리
                throw ex;
            }
            filterChain.doFilter(request, response); //
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

}
