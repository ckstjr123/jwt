package com.jwt.springsecurityjwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Redis와의 연결 정보를 설정,
 * Redis에 저장된 데이터를 저장하고 조회하는 데 사용되는 RedisTemplate 객체를 생성
 */
@Configuration
@RequiredArgsConstructor
public class RedisConfig {

    private final RedisProperties redisProperties; // Redis 서버와의 연결 정보를 저장하는 객체(yml에 설정한 host, post 정보 등)

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        // Redis Java 클라이언트 라이브러리인 Lettuce를 사용해서 Redis 서버와 연결해줌
        RedisStandaloneConfiguration redisStandaloneConfig = new RedisStandaloneConfiguration(redisProperties.getHost(), redisProperties.getPort());
        redisStandaloneConfig.setPassword(redisProperties.getPassword());
        return new LettuceConnectionFactory(redisStandaloneConfig);
    }

    /**
     * RedisTemplate은 Redis에 데이터를 저장하고 조회하는 기능을 하는 클래스
     * @return RedisTemplate
     */
    @Bean
    public RedisTemplate redisTemplate() {
        StringRedisTemplate stringRedisTemplate = new StringRedisTemplate();
        stringRedisTemplate.setConnectionFactory(this.redisConnectionFactory());
        return stringRedisTemplate;
    }
}