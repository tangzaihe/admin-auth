package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.LoginAttempt;

import java.time.Instant;
import java.util.Optional;

/**
 * 登录失败计数端口：标识+IP 维度一行，命中账号后回填 user_id；
 * user 维度通过累加同账号多行失败次数实现，避免换标识绕过锁定。
 */
public interface LoginAttemptRepository {

    Optional<LoginAttempt> findByIdentityHashAndIp(byte[] identityHash, String ip);

    /** 失败次数 +1（不存在则插入），返回最新次数。 */
    int incrementAndGet(byte[] identityHash, String ip, Long userId, Instant now);

    Optional<Instant> findLockedUntil(byte[] identityHash, String ip);

    void setLockedUntil(byte[] identityHash, String ip, Instant until);

    void clear(byte[] identityHash, String ip);

    Optional<Instant> findUserLockedUntil(long userId, String ip);

    int sumUserFailures(long userId, String ip);

    void clearUser(long userId, String ip);

    /** 管理员解锁：清除该账号在所有 IP 上的失败计数。 */
    void clearAllForUser(long userId);

    void lockUser(long userId, String ip, Instant until);
}
