package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.IdentityStatus;
import com.aseantec.adminauth.core.domain.IdentityType;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 登录标识仓储端口。
 * <p>登录查询只走盲索引 {@code value_hash}；写入时绝不写 {@code active_hash}（MySQL 生成列）。</p>
 */
public interface AdminIdentityRepository {

    Optional<AdminIdentity> findActiveByTypeAndHash(IdentityType type, byte[] valueHash);

    Optional<AdminIdentity> findById(long id);

    List<AdminIdentity> findByUserId(long userId);

    List<AdminIdentity> findActiveByUserId(long userId);

    long insert(AdminIdentity identity);

    void updateStatus(long id, IdentityStatus status);

    void updateVerifiedAt(long id, Instant at);
}
