package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.RecoveryCode;

import java.time.Instant;
import java.util.List;

/** 恢复码仓储端口：只存 HMAC 哈希，单次使用。 */
public interface RecoveryCodeRepository {

    void replaceForUser(long userId, List<String> codeHashes, Instant createdAt);

    List<RecoveryCode> findUnusedByUserId(long userId);

    boolean markUsed(long id, Instant at);

    void deleteByUserId(long userId);
}
