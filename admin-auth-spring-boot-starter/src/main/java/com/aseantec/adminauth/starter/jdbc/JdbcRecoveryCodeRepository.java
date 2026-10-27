package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.RecoveryCode;
import com.aseantec.adminauth.core.port.RecoveryCodeRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;

/** {@code adm_recovery_code} 的 JdbcTemplate 实现。 */
public class JdbcRecoveryCodeRepository implements RecoveryCodeRepository {

    private static final String COLUMNS = "id, user_id, code_hash, used_at, created_at";

    private final JdbcTemplate jdbc;

    private final RowMapper<RecoveryCode> mapper = (rs, rowNum) -> new RecoveryCode(
            rs.getLong("id"),
            rs.getLong("user_id"),
            rs.getString("code_hash"),
            JdbcSupport.instant(rs, "used_at"),
            JdbcSupport.instant(rs, "created_at"));

    public JdbcRecoveryCodeRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void replaceForUser(long userId, List<String> codeHashes, Instant createdAt) {
        jdbc.update("DELETE FROM adm_recovery_code WHERE user_id = ?", userId);
        for (String codeHash : codeHashes) {
            JdbcSupport.insert(jdbc,
                    "INSERT INTO adm_recovery_code (user_id, code_hash, used_at, created_at) VALUES (?,?,NULL,?)",
                    userId, codeHash, JdbcSupport.timestamp(createdAt));
        }
    }

    @Override
    public List<RecoveryCode> findUnusedByUserId(long userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_recovery_code WHERE user_id = ? AND used_at IS NULL "
                + "ORDER BY id", mapper, userId);
    }

    @Override
    public boolean markUsed(long id, Instant at) {
        return jdbc.update("UPDATE adm_recovery_code SET used_at = ? WHERE id = ? AND used_at IS NULL",
                JdbcSupport.timestamp(at), id) > 0;
    }

    @Override
    public void deleteByUserId(long userId) {
        jdbc.update("DELETE FROM adm_recovery_code WHERE user_id = ?", userId);
    }
}
