package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.FactorStatus;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.domain.MfaFactorType;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** 第二因素仓储端口。 */
public interface MfaFactorRepository {

    Optional<MfaFactor> findById(long id);

    List<MfaFactor> findByUserId(long userId);

    List<MfaFactor> findActiveByUserId(long userId);

    Optional<MfaFactor> findActiveByUserIdAndType(long userId, MfaFactorType type);

    Optional<MfaFactor> findPendingByUserIdAndType(long userId, MfaFactorType type);

    long insert(MfaFactor factor);

    void updateStatus(long id, FactorStatus status);

    void updateSecret(long id, byte[] secretEnc, int keyVersion);

    void activate(long id, Instant confirmedAt);

    /**
     * 原子推进已使用时间步：{@code UPDATE ... SET last_used_step = ? WHERE id = ? AND last_used_step < ?}。
     *
     * @return true=推进成功（首次使用该时间步）；false=已被使用过（重放）
     */
    boolean advanceLastUsedStep(long id, long step, Instant at);

    void recordFailure(long id, int failCount, Instant lockedUntil, Instant at);

    void resetFailure(long id, Instant at);

    void deleteByUserId(long userId);
}
