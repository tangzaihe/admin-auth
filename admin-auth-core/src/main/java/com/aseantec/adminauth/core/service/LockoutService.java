package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.LoginAttemptRepository;

import java.time.Duration;
import java.time.Instant;

/**
 * 登录锁定：默认 5 次失败 / 15 分钟锁定，标识+IP 与账号双维度。
 *
 * <p><b>链路</b>：登录前先查 {@link #isLocked} / {@link #isUserLocked} → 失败时
 * {@link #registerFailure} 原子累加，达到阈值同时锁定标识行与账号维度 →
 * 登录成功 {@link #clear} 清零。</p>
 *
 * <p><b>为何双维度</b>：三种标识都能登录，只按标识计数时攻击者可换标识绕过；
 * 账号维度通过累加同 user_id 多行失败次数实现。</p>
 */
public class LockoutService {

    private final LoginAttemptRepository repository;
    private final ClockProvider clock;
    private final AuditSink audit;
    private final int maxAttempts;
    private final Duration lockDuration;

    public LockoutService(LoginAttemptRepository repository,
                          ClockProvider clock,
                          AuditSink audit,
                          int maxAttempts,
                          Duration lockDuration) {
        this.repository = repository;
        this.clock = clock;
        this.audit = audit;
        this.maxAttempts = Math.max(1, maxAttempts);
        this.lockDuration = lockDuration == null ? Duration.ofMinutes(15) : lockDuration;
    }

    /** 标识+IP 是否处于锁定期；锁定期已过则清零计数，重新获得 5 次机会。 */
    public boolean isLocked(byte[] identityHash, String ip) {
        Instant now = clock.now();
        var lockedUntil = repository.findLockedUntil(identityHash, ip);
        if (lockedUntil.isPresent()) {
            if (lockedUntil.get().isAfter(now)) {
                return true;
            }
            repository.clear(identityHash, ip);
        }
        return false;
    }

    /** 账号维度是否处于锁定期（换标识不可绕过）；锁定期已过则清零该账号计数。 */
    public boolean isUserLocked(long userId, String ip) {
        Instant now = clock.now();
        var lockedUntil = repository.findUserLockedUntil(userId, ip);
        if (lockedUntil.isPresent()) {
            if (lockedUntil.get().isAfter(now)) {
                return true;
            }
            repository.clearUser(userId, ip);
            return false;
        }
        return repository.sumUserFailures(userId, ip) >= maxAttempts;
    }

    /**
     * 记录一次失败；达到阈值时同时锁定标识行与账号维度。
     *
     * @return 最新失败次数与是否已锁定
     */
    public FailureResult registerFailure(byte[] identityHash, String ip, Long userId) {
        Instant now = clock.now();
        int count = repository.incrementAndGet(identityHash, ip, userId, now);
        int userFailures = userId == null ? count : repository.sumUserFailures(userId, ip);
        boolean exceeded = count >= maxAttempts || (userId != null && userFailures >= maxAttempts);
        if (exceeded) {
            Instant until = now.plus(lockDuration);
            repository.setLockedUntil(identityHash, ip, until);
            if (userId != null) {
                repository.lockUser(userId, ip, until);
            }
            recordAudit(userId, now);
        }
        return new FailureResult(count, exceeded);
    }

    /** 登录成功后清零该标识与账号维度的失败计数（不删除审计）。 */
    public void clear(byte[] identityHash, String ip, Long userId) {
        repository.clear(identityHash, ip);
        if (userId != null) {
            repository.clearUser(userId, ip);
        }
    }

    /**
     * 该账号在窗口期内是否有密码失败（跨 IP），用于 ON_RISK 模式。
     *
     * @param window      统计窗口；null/0 表示不启用风险判定
     * @param minFailures 触发阈值（默认 1）
     */
    public boolean hasRecentFailures(long userId, Duration window, int minFailures) {
        if (window == null || window.isZero() || window.isNegative()) {
            return false;
        }
        int count = repository.countRecentFailures(userId, clock.now().minus(window));
        return count >= Math.max(1, minFailures);
    }

    /** 清除该账号所有 IP 的失败计数（MFA 成功后调用）。 */
    public void clearAllForUser(long userId) {
        repository.clearAllForUser(userId);
    }

    public int maxAttempts() {
        return maxAttempts;
    }

    public Duration lockDuration() {
        return lockDuration;
    }

    private void recordAudit(Long userId, Instant now) {
        try {
            audit.record(new AuditEntry(userId, userId, "", "", "", AuditEvent.LOCKED,
                    AuditResult.FAIL, "", "", "{\"reason\":\"TOO_MANY_ATTEMPTS\"}", now));
        } catch (RuntimeException ignored) {
            // 审计失败不影响锁定逻辑
        }
    }

    public record FailureResult(int count, boolean locked) {
    }
}
