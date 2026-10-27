package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.AuditEntry;

import java.util.List;

/** 审计流水仓储端口（只增不改）。 */
public interface AuditRepository {

    void append(AuditEntry entry);

    List<AuditEntry> findRecent(int limit);

    List<AuditEntry> findRecentByUser(long userId, int limit);
}
