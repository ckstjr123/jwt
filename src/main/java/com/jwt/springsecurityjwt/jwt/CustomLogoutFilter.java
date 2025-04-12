package com.jwt.springsecurityjwt.jwt;

import com.jwt.springsecurityjwt.service.RedisUtils;
import io.jsonwebtoken.lang.Assert;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

import static com.jwt.springsecurityjwt.entity.Member.MEMBER_REFRESH_TOKEN_PREFIX;

public class CustomLogoutFilter extends LogoutFilter {

    private final JwtUtils jwtUtils;
    private final RedisUtils redisUtils;

    public CustomLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, JwtUtils jwtUtils, RedisUtils redisUtils, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers);
        this.setLogoutRequestMatcher(new OrRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.POST.name())));
        this.jwtUtils = jwtUtils;
        this.redisUtils = redisUtils;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (this.requiresLogout((HttpServletRequest) request, (HttpServletResponse) response)) {
            this.doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Cookie rtCookie = WebUtils.getCookie(request, "refreshToken");

        if (rtCookie != null) {
            String refreshToken = rtCookie.getValue();
            if (StringUtils.hasText(refreshToken)) {
                Long memberId = Long.valueOf(this.jwtUtils.extractVaildClaims(refreshToken).getSubject());

                // Redis Lua script 사용해서 원자적인 명령어로 묶을 수 있음
                String findRefreshToken = this.redisUtils.getValue(MEMBER_REFRESH_TOKEN_PREFIX + memberId);
                if (refreshToken.equals(findRefreshToken)) {
                    this.redisUtils.deleteData(MEMBER_REFRESH_TOKEN_PREFIX + memberId);
                }
            }

            new CookieClearingLogoutHandler("refreshToken").logout(request, response, null);
        }
    }

}
