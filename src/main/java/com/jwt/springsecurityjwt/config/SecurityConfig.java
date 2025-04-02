package com.jwt.springsecurityjwt.config;

import com.jwt.springsecurityjwt.constant.Role;
import com.jwt.springsecurityjwt.jwt.JwtAuthenticationFilter;
import com.jwt.springsecurityjwt.jwt.JwtUtils;
import com.jwt.springsecurityjwt.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtils jwtUtils;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // cross-origin resource sharing(교차 출처 리소스 공유) 허용하도록 설정
        http
                .cors((cors) -> cors
                        .configurationSource(request -> {
                            CorsConfiguration corsConfig = new CorsConfiguration();

                            corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                            corsConfig.setAllowedMethods(Collections.singletonList("*"));
                            corsConfig.setAllowCredentials(true);
                            corsConfig.setAllowedHeaders(Collections.singletonList("*"));
                            corsConfig.setMaxAge(3600L);

                            corsConfig.setExposedHeaders(Collections.singletonList(HttpHeaders.AUTHORIZATION));
                            return corsConfig;
                        }));


        http
                .csrf((auth) -> auth.disable());

        http
                .exceptionHandling(config -> config.authenticationEntryPoint(this.authenticationEntryPoint));

        http
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/refresh").permitAll()
                        .requestMatchers("/admin").hasAuthority(Role.ADMIN)
                        .anyRequest().authenticated());

        http
                .addFilterBefore(new JwtAuthenticationFilter(this.jwtUtils), LoginFilter.class)
                .addFilterAt(new LoginFilter(this.authenticationManager(authenticationConfiguration), this.jwtUtils), UsernamePasswordAuthenticationFilter.class);

        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }


}
