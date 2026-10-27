package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.port.AuditRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.util.List;

/** {@code adm_audit_log} 的 JdbcTemplate 实现（只增不改）。 */
public class JdbcAuditRepository implements AuditRepository {

    private static final String COLUMNS = "id, user_id, actor_user_id, identity_type, factor_type, channel_mask, "
            + "event, result, ip, user_agent, detail, created_at";

    private final JdbcTemplate jdbc;

    private final RowMapper<AuditEntry> mapper = (rs, rowNum) -> new AuditEntry(
            (Long) rs.getObject("user_id"),
            (Long) rs.getObject("actor_user_id"),
            rs.getString("identity_type"),
            rs.getString("factor_type"),
            rs.getString("channel_mask"),
            AuditEvent.valueOf(rs.getString("event")),
            AuditResult.valueOf(rs.getString("result")),
            rs.getString("ip"),
            rs.getString("user_agent"),
            rs.getString("detail"),
            JdbcSupport.instant(rs, "created_at"));

    public JdbcAuditRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void append(AuditEntry entry) {
        JdbcSupport.insert(jdbc,
                "INSERT INTO adm_audit_log (user_id, actor_user_id, identity_type, factor_type, channel_mask, "
                        + "event, result, ip, user_agent, detail, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                entry.userId(),
                entry.actorUserId(),
                entry.identityType(),
                entry.factorType(),
                entry.channelMask(),
                entry.event().name(),
                entry.result().name(),
                JdbcSupport.truncate(entry.ip(), 45),
                JdbcSupport.truncate(entry.userAgent(), 255),
                JdbcSupport.nullIfBlank(entry.detail()),
                JdbcSupport.timestamp(entry.createdAt()));
    }

    @Override
    public List<AuditEntry> findRecent(int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_audit_log ORDER BY id DESC LIMIT ?",
                mapper, Math.max(1, Math.min(limit, 500)));
    }

    @Override
    public List<AuditEntry> findRecentByUser(long userId, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                mapper, userId, Math.max(1, Math.min(limit, 500)));
    }
}
