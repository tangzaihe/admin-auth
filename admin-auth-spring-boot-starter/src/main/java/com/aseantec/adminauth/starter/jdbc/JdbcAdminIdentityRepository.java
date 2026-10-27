package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.IdentityStatus;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.port.AdminIdentityRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * {@code adm_identity} 的 JdbcTemplate 实现。
 * <p><b>注意</b>：INSERT/UPDATE 永不包含 {@code active_hash}（MySQL 生成列，第 8 段坑 ②）；
 * H2 demo 中该列为普通 NULL 列。</p>
 */
public class JdbcAdminIdentityRepository implements AdminIdentityRepository {

    private static final String COLUMNS = "id, user_id, identity_type, value_enc, key_version, value_hash, "
            + "value_mask, verified_at, consent_at, consent_version, is_primary, status";

    private final JdbcTemplate jdbc;

    private final RowMapper<AdminIdentity> mapper = (rs, rowNum) -> new AdminIdentity(
            rs.getLong("id"),
            rs.getLong("user_id"),
            IdentityType.valueOf(rs.getString("identity_type")),
            rs.getBytes("value_enc"),
            rs.getInt("key_version"),
            rs.getBytes("value_hash"),
            rs.getString("value_mask"),
            JdbcSupport.instant(rs, "verified_at"),
            JdbcSupport.instant(rs, "consent_at"),
            rs.getString("consent_version"),
            rs.getInt("is_primary") == 1,
            IdentityStatus.fromCode(rs.getInt("status")));

    public JdbcAdminIdentityRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<AdminIdentity> findActiveByTypeAndHash(IdentityType type, byte[] valueHash) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_identity "
                        + "WHERE identity_type = ? AND value_hash = ? AND status = 1",
                mapper, type.name(), valueHash).stream().findFirst();
    }

    @Override
    public Optional<AdminIdentity> findById(long id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_identity WHERE id = ?", mapper, id).stream().findFirst();
    }

    @Override
    public List<AdminIdentity> findByUserId(long userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_identity WHERE user_id = ? ORDER BY identity_type, id",
                mapper, userId);
    }

    @Override
    public List<AdminIdentity> findActiveByUserId(long userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_identity WHERE user_id = ? AND status = 1 "
                + "ORDER BY identity_type, id", mapper, userId);
    }

    @Override
    public long insert(AdminIdentity identity) {
        Instant now = Instant.now();
        return JdbcSupport.insert(jdbc,
                "INSERT INTO adm_identity (user_id, identity_type, value_enc, key_version, value_hash, value_mask, "
                        + "verified_at, consent_at, consent_version, is_primary, status, created_at, updated_at) "
                        + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                identity.userId(),
                identity.identityType().name(),
                identity.valueEnc(),
                identity.keyVersion(),
                identity.valueHash(),
                identity.valueMask(),
                identity.verifiedAt(),
                identity.consentAt(),
                identity.consentVersion() == null ? "" : identity.consentVersion(),
                identity.primary() ? 1 : 0,
                identity.status().code(),
                JdbcSupport.timestamp(now),
                JdbcSupport.timestamp(now));
    }

    @Override
    public void updateStatus(long id, IdentityStatus status) {
        jdbc.update("UPDATE adm_identity SET status = ?, updated_at = ? WHERE id = ?",
                status.code(), JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateVerifiedAt(long id, Instant at) {
        jdbc.update("UPDATE adm_identity SET verified_at = ?, updated_at = ? WHERE id = ?",
                JdbcSupport.timestamp(at), JdbcSupport.timestamp(Instant.now()), id);
    }
}
