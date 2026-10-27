package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.LoginAttempt;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.LoginAttemptRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** 登录锁定：5 次/15 分钟，标识+IP 与账号双维度，成功清零。 */
class LockoutServiceTest {

    private static final byte[] IDENTITY_A = "identity-a".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IDENTITY_B = "identity-b".getBytes(StandardCharsets.UTF_8);
    private static final String IP = "10.0.0.8";
    private static final AuditSink NO_AUDIT = entry -> {
    };

    private final MutableClock clock = new MutableClock();
    private final InMemoryAttemptRepository repository = new InMemoryAttemptRepository();
    private final LockoutService lockout = new LockoutService(repository, clock, NO_AUDIT,
            5, Duration.ofMinutes(15));

    @Test
    @DisplayName("5 次失败触发锁定：标识维度与账号维度同时锁定")
    void fiveFailuresLockBothDimensions() {
        for (int i = 1; i <= 4; i++) {
            assertThat(lockout.registerFailure(IDENTITY_A, IP, 1L).locked()).isFalse();
        }
        LockoutService.FailureResult fifth = lockout.registerFailure(IDENTITY_A, IP, 1L);
        assertThat(fifth.locked()).isTrue();
        assertThat(fifth.count()).isEqualTo(5);
        assertThat(lockout.isLocked(IDENTITY_A, IP)).isTrue();
        assertThat(lockout.isUserLocked(1L, IP)).isTrue();
    }

    @Test
    @DisplayName("换标识不可绕过：同一账号不同标识的失败次数合并计算")
    void userDimensionAggregatesAcrossIdentities() {
        for (int i = 0; i < 3; i++) {
            lockout.registerFailure(IDENTITY_A, IP, 1L);
        }
        // 换一个标识继续尝试：第 5 次时账号维度命中阈值
        lockout.registerFailure(IDENTITY_B, IP, 1L);
        LockoutService.FailureResult fifth = lockout.registerFailure(IDENTITY_B, IP, 1L);

        assertThat(fifth.locked()).isTrue();
        assertThat(lockout.isUserLocked(1L, IP)).isTrue();
        assertThat(lockout.isLocked(IDENTITY_B, IP)).isTrue();
        // 该账号的其它标识也被 user 维度挡住
        assertThat(lockout.isUserLocked(1L, IP)).isTrue();
    }

    @Test
    @DisplayName("锁定到期自动解除")
    void lockExpires() {
        for (int i = 0; i < 5; i++) {
            lockout.registerFailure(IDENTITY_A, IP, 1L);
        }
        assertThat(lockout.isLocked(IDENTITY_A, IP)).isTrue();

        clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        assertThat(lockout.isLocked(IDENTITY_A, IP)).isFalse();
        assertThat(lockout.isUserLocked(1L, IP)).isFalse();
    }

    @Test
    @DisplayName("登录成功清零标识与账号维度计数")
    void successClearsCounters() {
        for (int i = 0; i < 3; i++) {
            lockout.registerFailure(IDENTITY_A, IP, 1L);
        }
        lockout.clear(IDENTITY_A, IP, 1L);

        assertThat(repository.sumUserFailures(1L, IP)).isZero();
        assertThat(lockout.isLocked(IDENTITY_A, IP)).isFalse();
    }

    @Test
    @DisplayName("账号不存在（user_id 为空）只累计标识维度，不影响任何账号")
    void anonymousFailureOnlyCountsIdentity() {
        for (int i = 0; i < 5; i++) {
            lockout.registerFailure(IDENTITY_A, IP, null);
        }
        assertThat(lockout.isLocked(IDENTITY_A, IP)).isTrue();
        assertThat(lockout.isUserLocked(1L, IP)).isFalse();
    }

    // ---------- in-memory fixtures ----------

    private static final class MutableClock implements ClockProvider {
        private Instant now = Instant.parse("2026-10-27T12:00:00Z");

        @Override
        public Instant now() {
            return now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }
    }

    private static final class InMemoryAttemptRepository implements LoginAttemptRepository {

        private static final class Row {
            Long userId;
            byte[] identityHash;
            String ip;
            int failCount;
            Instant lockedUntil;
            Instant updatedAt;
        }

        private final Map<String, Row> rows = new LinkedHashMap<>();

        @Override
        public Optional<LoginAttempt> findByIdentityHashAndIp(byte[] identityHash, String ip) {
            Row row = rows.get(key(identityHash, ip));
            return row == null ? Optional.empty() : Optional.of(toRecord(row));
        }

        @Override
        public int incrementAndGet(byte[] identityHash, String ip, Long userId, Instant now) {
            Row row = rows.computeIfAbsent(key(identityHash, ip), ignored -> {
                Row created = new Row();
                created.identityHash = identityHash;
                created.ip = ip;
                created.updatedAt = now;
                return created;
            });
            row.failCount++;
            row.updatedAt = now;
            if (userId != null) {
                row.userId = userId;
            }
            return row.failCount;
        }

        @Override
        public Optional<Instant> findLockedUntil(byte[] identityHash, String ip) {
            Row row = rows.get(key(identityHash, ip));
            return row == null ? Optional.empty() : Optional.ofNullable(row.lockedUntil);
        }

        @Override
        public void setLockedUntil(byte[] identityHash, String ip, Instant until) {
            Row row = rows.get(key(identityHash, ip));
            if (row != null) {
                row.lockedUntil = until;
            }
        }

        @Override
        public void clear(byte[] identityHash, String ip) {
            rows.remove(key(identityHash, ip));
        }

        @Override
        public Optional<Instant> findUserLockedUntil(long userId, String ip) {
            return rows.values().stream()
                    .filter(row -> row.userId != null && row.userId == userId && ip.equals(row.ip))
                    .map(row -> row.lockedUntil)
                    .filter(java.util.Objects::nonNull)
                    .max(Instant::compareTo);
        }

        @Override
        public int sumUserFailures(long userId, String ip) {
            return rows.values().stream()
                    .filter(row -> row.userId != null && row.userId == userId && ip.equals(row.ip))
                    .mapToInt(row -> row.failCount)
                    .sum();
        }

        @Override
        public void clearUser(long userId, String ip) {
            rows.values().removeIf(row -> row.userId != null && row.userId == userId && ip.equals(row.ip));
        }

        @Override
        public void clearAllForUser(long userId) {
            rows.values().removeIf(row -> row.userId != null && row.userId == userId);
        }

        @Override
        public void lockUser(long userId, String ip, Instant until) {
            rows.values().stream()
                    .filter(row -> row.userId != null && row.userId == userId && ip.equals(row.ip))
                    .forEach(row -> row.lockedUntil = until);
        }

        private String key(byte[] hash, String ip) {
            return HexFormat.of().formatHex(hash) + "|" + ip;
        }

        private LoginAttempt toRecord(Row row) {
            return new LoginAttempt(0L, row.userId, row.identityHash, row.ip, row.failCount,
                    row.lockedUntil, row.updatedAt);
        }
    }
}
