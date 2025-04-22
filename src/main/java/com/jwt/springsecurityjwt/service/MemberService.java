package com.jwt.springsecurityjwt.service;

import com.jwt.springsecurityjwt.constant.Role;
import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.entity.Member;
import com.jwt.springsecurityjwt.exception.AuthenticationException;
import com.jwt.springsecurityjwt.exception.RefreshViolationException;
import com.jwt.springsecurityjwt.exception.response.AuthExceptionType;
import com.jwt.springsecurityjwt.jwt.JwtProvider;
import com.jwt.springsecurityjwt.jwt.JwtUser;
import com.jwt.springsecurityjwt.jwt.vo.JwtReissueRequest;
import com.jwt.springsecurityjwt.jwt.vo.JwtResponse;
import com.jwt.springsecurityjwt.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.jwt.springsecurityjwt.entity.Member.MEMBER_REFRESH_TOKEN_PREFIX;
import static com.jwt.springsecurityjwt.exception.response.AuthExceptionType.VIOLATE_REFRESH_JWT;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final JwtProvider jwtProvider;
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
        Claims rtClaims = this.jwtProvider.extractVaildClaims(refreshToken);

        JwtUser refreshUserInfo = JwtUser.from(rtClaims);
        Long memberId = refreshUserInfo.getMemberId();

        String savedRefreshToken = this.redisUtils.getValue(MEMBER_REFRESH_TOKEN_PREFIX + memberId);
        if (savedRefreshToken == null) {
            throw new AuthenticationException(AuthExceptionType.EXPIRED_JWT);
        } else if (!savedRefreshToken.equals(refreshToken)) {
            this.redisUtils.deleteData(MEMBER_REFRESH_TOKEN_PREFIX + memberId); // (해당하는 유효한 요청 갱신 토큰을 블랙리스트에 등록하는 작업으로 대체할 수 있음)
            throw new RefreshViolationException(VIOLATE_REFRESH_JWT);
        }

        return this.refreshTokenRotation(memberId, refreshUserInfo.getUsername(), refreshUserInfo.getRole());
    }

    private JwtResponse refreshTokenRotation(Long memberId, String username, String role) {
        String accessToken = "Bearer " + this.jwtProvider.issueAccessToken(memberId, username, role);
        String rotateRefreshToken = this.jwtProvider.issueRefreshToken(memberId);
        this.redisUtils.setDataExpire(MEMBER_REFRESH_TOKEN_PREFIX + memberId, rotateRefreshToken, JwtProvider.REFRESH_TOKEN_EXPIRE_MS);
        return new JwtResponse(accessToken, rotateRefreshToken);
    }

}
