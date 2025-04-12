package com.jwt.springsecurityjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisUtils {

    private final RedisTemplate<String, String> stringRedisTemplate; // from RedisConfig

    /**
     * key를 통해 value 조회
     * @param key
     * @return String
     */
    public String getValue(String key) {
        ValueOperations<String, String> valueOperations = this.stringRedisTemplate.opsForValue();
        return valueOperations.get(key);
    }

    /**
     * {key, value} 데이터를 Redis에 저장
     * (If key already holds a value, it is overwritten)
     * @param key
     * @param value
     */
    public void setData(String key, String value) {
        ValueOperations<String, String> valueOperations = this.stringRedisTemplate.opsForValue();
        valueOperations.set(key, value);
    }

    /**
     * 유효 시간(duration)을 지정할 {key, value} 데이터 저장
     * @param key
     * @param value
     * @param timeoutSeconds
     */
    public void setDataExpire(String key, String value, long timeoutSeconds) {
        ValueOperations<String, String> valueOperations = this.stringRedisTemplate.opsForValue();
        Duration expireDuration = Duration.ofSeconds(timeoutSeconds);
        valueOperations.set(key, value, expireDuration);
    }

    /**
     * {key : value} 데이터 삭제
     * @param key
     */
    public void deleteData(String key) {
        this.stringRedisTemplate.delete(key);
    }

    /**
     * 해당 key로 된 데이터가 저장되어 있는지 여부
     * @param key
     * @return boolean
     */
    public boolean isExists(String key) {
        return Boolean.TRUE.equals(this.stringRedisTemplate.hasKey(key));
    }

}