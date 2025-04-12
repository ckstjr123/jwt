package com.jwt.springsecurityjwt.service;

import com.jwt.springsecurityjwt.constant.Role;
import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.entity.Member;
import com.jwt.springsecurityjwt.exception.AuthenticationException;
import com.jwt.springsecurityjwt.exception.response.AuthExceptionType;
import com.jwt.springsecurityjwt.jwt.JwtUser;
import com.jwt.springsecurityjwt.jwt.JwtUtils;
import com.jwt.springsecurityjwt.jwt.vo.JwtReissueRequest;
import com.jwt.springsecurityjwt.jwt.vo.JwtResponse;
import com.jwt.springsecurityjwt.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.jwt.springsecurityjwt.entity.Member.MEMBER_REFRESH_TOKEN_PREFIX;
import static com.jwt.springsecurityjwt.jwt.JwtUtils.ACCESS_TOKEN_EXPIRED_MS;
import static com.jwt.springsecurityjwt.jwt.JwtUtils.REFRESH_TOKEN_EXPIRED_MS;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final JwtUtils jwtUtils;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final RedisUtils redisUtils;

    @Transactional
    public Long join(MemberJoinDto memberJoinDto) {
        String username = memberJoinDto.getUsername();
        String password = memberJoinDto.getPassword();

        if (this.memberRepository.existsByUsername(username)) {
            throw new IllegalStateException("이미 존재하는 회원입니다.");
        }

        Member member = Member.createMember(username, this.passwordEncoder.encode(password), Role.ADMIN);
        this.memberRepository.save(member);
        return member.getId();
    }

    @Transactional
    public JwtResponse refresh(JwtReissueRequest tokenRefreshRequest) {
        //refresh token 검증 수행됨(만료 등 예외 처리를 위해 ExceptionHandler 등록 필요)
        String refreshToken = tokenRefreshRequest.getRefreshToken();
        Claims rtClaims = this.jwtUtils.extractVaildClaims(refreshToken);

        JwtUser refreshUserInfo = JwtUser.from(rtClaims);
        Long memberId = refreshUserInfo.getMemberId();

        String savedRefreshToken = this.redisUtils.getValue(MEMBER_REFRESH_TOKEN_PREFIX + memberId);
        if (savedRefreshToken == null) {
            throw new AuthenticationException(AuthExceptionType.EXPIRED_JWT);
        } else if (!savedRefreshToken.equals(refreshToken)) {
            this.redisUtils.deleteData(MEMBER_REFRESH_TOKEN_PREFIX + memberId);
            throw new AuthenticationException(AuthExceptionType.INVALID_JWT); // 400
        }

        return this.refreshTokenRotation(memberId, refreshUserInfo.getUsername(), refreshUserInfo.getRole());
    }

    private JwtResponse refreshTokenRotation(Long memberId, String username, String role) {
        String accessToken = "Bearer " + this.jwtUtils.generateJwt(memberId, username, role, ACCESS_TOKEN_EXPIRED_MS);
        String rotateRefreshToken = this.jwtUtils.generateJwt(memberId, username, role, REFRESH_TOKEN_EXPIRED_MS);
        this.redisUtils.setDataExpire(MEMBER_REFRESH_TOKEN_PREFIX + memberId, rotateRefreshToken, REFRESH_TOKEN_EXPIRED_MS);
        return new JwtResponse(accessToken, rotateRefreshToken);
    }

}
