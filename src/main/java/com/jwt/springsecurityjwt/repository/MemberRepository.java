package com.jwt.springsecurityjwt.repository;

import com.jwt.springsecurityjwt.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    boolean existsByUsername(String username);

    Optional<Member> findByUsername(String username);

    String findByRefreshToken(String refreshToken);

    void deleteByRefreshToken(String refreshToken);
}
