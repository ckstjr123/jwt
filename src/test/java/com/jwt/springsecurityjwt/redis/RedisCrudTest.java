package com.jwt.springsecurityjwt.redis;

import com.jwt.springsecurityjwt.service.RedisUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest
class RedisCrudTest {

    private final String KEY = "key";
    private final String VALUE = "value";

    @Autowired
    private RedisUtils redisUtils;

    @AfterEach
    void clear() {
        this.redisUtils.deleteData(KEY);
    }

    @Test
    @DisplayName("Redis에 데이터를 저장 및 조회할 수 있음")
    void saveAndFind() {
        // given
        this.redisUtils.setData(KEY, VALUE);

        // when
        String findValue = this.redisUtils.getValue(KEY);

        // then
        log.info("findValue: {}", findValue);
        assertThat(VALUE).isEqualTo(findValue);
    }

    @Test
    @DisplayName("Redis에 저장된 데이터를 수정할 수 있음")
    void update() {
        // given
        this.redisUtils.setData(KEY, VALUE);
        assertThat(this.redisUtils.getValue(KEY)).isEqualTo(VALUE);

        // when
        String updateValue = "updateValue";
        this.redisUtils.setData(KEY, updateValue);

        // then
        String findValue = this.redisUtils.getValue(KEY);
        log.info("findValue: {}", findValue);
        assertThat(findValue).isEqualTo(updateValue);
    }

    @Test
    @DisplayName("Redis에 저장된 데이터를 삭제할 수 있음")
    void delete() {
        // given
        this.redisUtils.setData(KEY, VALUE);
        assertThat(this.redisUtils.getValue(KEY)).isEqualTo(VALUE);

        // when
        this.redisUtils.deleteData(KEY);
        String findValue = this.redisUtils.getValue(KEY);

        // then
        log.info("deletedValue: {}", findValue);
        assertThat(findValue).isNull();
    }

    @Test
    @DisplayName("Redis에 해당 key로 저장된 데이터가 있는지 여부를 확인할 수 있음")
    void isExists() {
        // given
        this.redisUtils.setData(KEY, VALUE);
        log.info("data is exists: " + this.redisUtils.getValue(KEY));

        // then
        assertThat(this.redisUtils.isExists(KEY)).isTrue();

        // and then given
        this.redisUtils.deleteData(KEY);
        log.info("data is deleted: " + this.redisUtils.getValue(KEY));

        // then
        assertThat(this.redisUtils.isExists(KEY)).isFalse();
    }

    @Test
    @DisplayName("Redis에 유효기간이 지정된 데이터는 만료 시 삭제됨")
    void expire() throws InterruptedException {
        // given
        this.redisUtils.setDataExpire(KEY, VALUE, 5); // 데이터 유효시간 5초

        // when
        String findValue = this.redisUtils.getValue(KEY);
        assertThat(findValue).isEqualTo(VALUE);
        log.info("findValue: {}", findValue);
        Thread.sleep(10000);

        // then
        String expiredValue = this.redisUtils.getValue(KEY);
        log.info("expiredValue: {}", expiredValue);
        assertThat(expiredValue).isNull();
    }

}