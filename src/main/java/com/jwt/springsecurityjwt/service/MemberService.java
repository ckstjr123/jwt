package com.jwt.springsecurityjwt.service;

import com.jwt.springsecurityjwt.constant.Role;
import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.entity.Member;
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

@Service
@RequiredArgsConstructor
public class MemberService {

    private final JwtUtils jwtUtils;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

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
        // 리프레시 토큰 검증 수행됨(만료 등 예외 처리를 위해 ExceptionHandler 등록 필요)
        Claims refreshTokenClaims = this.jwtUtils.extractVaildClaims(tokenRefreshRequest.getRefreshToken());

        // !hasText("EXPIRED") -> 저장된 리프레시 토큰과 일치하는지 검증(일치하지 않으면 "EXPIRED" 업데이트 처리) -> 400 응답 //

        JwtUser refreshUserInfo = JwtUser.from(refreshTokenClaims);
        Long memberId = refreshUserInfo.getMemberId();
        String username = refreshUserInfo.getUsername();
        String role = refreshUserInfo.getRole();

        String accessToken = "Bearer " + this.jwtUtils.generateJwt(memberId, username, role, JwtUtils.accessTokenExpiredMs);
        String refreshToken = this.jwtUtils.generateJwt(memberId, username, role, JwtUtils.refreshTokenExpiredMs);
        return new JwtResponse(accessToken, refreshToken);
    }

}
