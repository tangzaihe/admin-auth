package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.port.AuditRepository;
import com.aseantec.adminauth.core.port.AuditSink;

/** 默认审计 SPI：写 {@code adm_audit_log}，可被宿主 Bean 覆盖。 */
public class JdbcAuditSink implements AuditSink {

    private final AuditRepository repository;

    public JdbcAuditSink(AuditRepository repository) {
        this.repository = repository;
    }

    @Override
    public void record(AuditEntry entry) {
        repository.append(entry);
    }
}
