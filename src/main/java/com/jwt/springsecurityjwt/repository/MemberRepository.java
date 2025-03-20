package com.jwt.springsecurityjwt.repository;

import com.jwt.springsecurityjwt.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

    boolean existsByUsername(String username);
}
