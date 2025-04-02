package com.jwt.springsecurityjwt.service;

import com.jwt.springsecurityjwt.entity.Member;
import com.jwt.springsecurityjwt.jwt.CustomUserDetails;
import com.jwt.springsecurityjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;


@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member findMember = this.memberRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        return new CustomUserDetails(findMember.getId(), findMember.getUsername(), findMember.getPassword(), Set.of(new SimpleGrantedAuthority(findMember.getRole())));
    }
}
