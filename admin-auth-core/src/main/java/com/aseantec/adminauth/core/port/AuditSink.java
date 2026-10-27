package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.AuditEntry;

/** 审计落库 SPI（默认实现写 {@code adm_audit_log}，宿主可覆盖）。 */
public interface AuditSink {

    void record(AuditEntry entry);
}
