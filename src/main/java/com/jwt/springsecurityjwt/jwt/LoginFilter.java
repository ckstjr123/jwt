package com.jwt.springsecurityjwt.jwt;

import com.jwt.springsecurityjwt.service.RedisUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

import static com.jwt.springsecurityjwt.entity.Member.MEMBER_REFRESH_TOKEN_PREFIX;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final RedisUtils redisUtils;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = this.obtainUsername(request);
        String password = this.obtainPassword(request);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        return this.authenticationManager.authenticate(authToken); //AuthenticationManager 통해 검증
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();

        Long memberId = userDetails.getId();
        String username = userDetails.getUsername();
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .toList();
        GrantedAuthority grantedAuthority = userDetails.getAuthorities().iterator().next();
        String role = grantedAuthority.getAuthority();
        
        //access & refresh 토큰 발행
        String accessToken = this.jwtProvider.issueAccessToken(memberId, username, role);
        String refreshToken = this.jwtProvider.issueRefreshToken(memberId);

        this.saveRefreshToken(memberId, refreshToken); // refresh token TTL 지정해서 레디스에 저장

        //토큰 발급(모바일의 경우 모든 토큰을 헤더로 전달)
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken); // '액세스 토큰은 헤더로' 전달
        response.addCookie(this.createCookie("refreshToken", refreshToken)); // '리프레시 토큰은 쿠키에' 담아서 전달
        response.setStatus(HttpStatus.OK.value());

        log.info("login success: {}", username);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }


    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(3 * 60);
//        cookie.setSecure(true); // https 통신 사용할 경우 설정
//        cookie.setPath("/"); // 쿠키가 적용될 경로
        cookie.setHttpOnly(true);
        return cookie;
    }

    private void saveRefreshToken(Long memberId, String refreshToken) {
        this.redisUtils.setDataExpire(MEMBER_REFRESH_TOKEN_PREFIX + memberId, refreshToken, JwtProvider.REFRESH_TOKEN_EXPIRE_MS);
    }

}
