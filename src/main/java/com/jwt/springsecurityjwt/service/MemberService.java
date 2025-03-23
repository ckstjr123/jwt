package com.jwt.springsecurityjwt.service;

import com.jwt.springsecurityjwt.dto.MemberJoinDto;
import com.jwt.springsecurityjwt.entity.Member;
import com.jwt.springsecurityjwt.repository.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public Long join(MemberJoinDto memberJoinDto) {
        String username = memberJoinDto.getUsername();
        String password = memberJoinDto.getPassword();

        if (this.memberRepository.existsByUsername(username)) {
            throw new IllegalStateException("이미 존재하는 회원입니다.");
        }

        Member member = new Member();
        member.setUsername(username);
        member.setPassword(this.passwordEncoder.encode(password));
        member.setRole("ADMIN");

        this.memberRepository.save(member);
        return member.getId();
    }

}
