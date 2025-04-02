package com.jwt.springsecurityjwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.lang.Assert;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUser {

    private Long memberId;
    private String username;
    private String role;

    public static JwtUserBuilder builder() {
        return new JwtUserBuilder();
    }

    public static JwtUser from(Claims claims) {
        Assert.notEmpty(claims, "claims cannot be empty");
        return JwtUser.builder()
                .memberId(Long.valueOf(claims.getSubject()))
                .username(claims.get("username", String.class))
                .role(claims.get("role", String.class))
                .build();
    }

    public static class JwtUserBuilder {

        private final JwtUser jwtUser;

        private JwtUserBuilder() {
            this.jwtUser = new JwtUser();
        }

        public JwtUserBuilder memberId(Long memberId) {
            this.jwtUser.memberId = memberId;
            return this;
        }

        public JwtUserBuilder username(String username) {
            this.jwtUser.username = username;
            return this;
        }

        public JwtUserBuilder role(String role) {
            this.jwtUser.role = role;
            return this;
        }
        public JwtUser build() {
            return this.jwtUser;
        }

    }

}
