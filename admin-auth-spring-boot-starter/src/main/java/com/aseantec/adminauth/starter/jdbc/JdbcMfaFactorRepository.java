package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.FactorStatus;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import com.aseantec.adminauth.core.port.MfaFactorRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** {@code adm_mfa_factor} 的 JdbcTemplate 实现（{@code advanceLastUsedStep} 为原子 UPDATE）。 */
public class JdbcMfaFactorRepository implements MfaFactorRepository {

    private static final String COLUMNS = "id, user_id, factor_type, identity_id, secret_enc, key_version, "
            + "digits, period, last_used_step, payload, priority, confirmed_at, fail_count, locked_until, status";

    private final JdbcTemplate jdbc;

    private final RowMapper<MfaFactor> mapper = (rs, rowNum) -> new MfaFactor(
            rs.getLong("id"),
            rs.getLong("user_id"),
            MfaFactorType.valueOf(rs.getString("factor_type")),
            rs.getLong("identity_id"),
            rs.getBytes("secret_enc"),
            rs.getInt("key_version"),
            rs.getInt("digits"),
            rs.getInt("period"),
            rs.getLong("last_used_step"),
            rs.getString("payload"),
            rs.getInt("priority"),
            JdbcSupport.instant(rs, "confirmed_at"),
            rs.getInt("fail_count"),
            JdbcSupport.instant(rs, "locked_until"),
            FactorStatus.fromCode(rs.getInt("status")));

    public JdbcMfaFactorRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<MfaFactor> findById(long id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_mfa_factor WHERE id = ?", mapper, id).stream().findFirst();
    }

    @Override
    public List<MfaFactor> findByUserId(long userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_mfa_factor WHERE user_id = ? ORDER BY priority, id",
                mapper, userId);
    }

    @Override
    public List<MfaFactor> findActiveByUserId(long userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_mfa_factor WHERE user_id = ? AND status = 1 "
                + "ORDER BY priority, id", mapper, userId);
    }

    @Override
    public Optional<MfaFactor> findActiveByUserIdAndType(long userId, MfaFactorType type) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_mfa_factor "
                        + "WHERE user_id = ? AND factor_type = ? AND status = 1 ORDER BY id",
                mapper, userId, type.name()).stream().findFirst();
    }

    @Override
    public Optional<MfaFactor> findPendingByUserIdAndType(long userId, MfaFactorType type) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_mfa_factor "
                        + "WHERE user_id = ? AND factor_type = ? AND status = 2 ORDER BY id",
                mapper, userId, type.name()).stream().findFirst();
    }

    @Override
    public long insert(MfaFactor factor) {
        Instant now = Instant.now();
        return JdbcSupport.insert(jdbc,
                "INSERT INTO adm_mfa_factor (user_id, factor_type, identity_id, secret_enc, key_version, digits, "
                        + "period, last_used_step, payload, priority, confirmed_at, fail_count, locked_until, status, "
                        + "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                factor.userId(),
                factor.factorType().name(),
                factor.identityId(),
                factor.secretEnc(),
                factor.keyVersion(),
                factor.digits(),
                factor.period(),
                factor.lastUsedStep(),
                JdbcSupport.nullIfBlank(factor.payload()),
                factor.priority(),
                factor.confirmedAt(),
                factor.failCount(),
                factor.lockedUntil(),
                factor.status().code(),
                JdbcSupport.timestamp(now),
                JdbcSupport.timestamp(now));
    }

    @Override
    public void updateStatus(long id, FactorStatus status) {
        jdbc.update("UPDATE adm_mfa_factor SET status = ?, updated_at = ? WHERE id = ?",
                status.code(), JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateSecret(long id, byte[] secretEnc, int keyVersion) {
        jdbc.update("UPDATE adm_mfa_factor SET secret_enc = ?, key_version = ?, updated_at = ? WHERE id = ?",
                secretEnc, keyVersion, JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void activate(long id, Instant confirmedAt) {
        Instant now = Instant.now();
        jdbc.update("UPDATE adm_mfa_factor SET status = 1, confirmed_at = ?, fail_count = 0, locked_until = NULL, "
                        + "updated_at = ? WHERE id = ?",
                JdbcSupport.timestamp(confirmedAt), JdbcSupport.timestamp(now), id);
    }

    @Override
    public boolean advanceLastUsedStep(long id, long step, Instant at) {
        return jdbc.update("UPDATE adm_mfa_factor SET last_used_step = ?, updated_at = ? "
                + "WHERE id = ? AND last_used_step < ?",
                step, JdbcSupport.timestamp(at), id, step) > 0;
    }

    @Override
    public void recordFailure(long id, int failCount, Instant lockedUntil, Instant at) {
        jdbc.update("UPDATE adm_mfa_factor SET fail_count = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                failCount, JdbcSupport.timestamp(lockedUntil), JdbcSupport.timestamp(at), id);
    }

    @Override
    public void resetFailure(long id, Instant at) {
        jdbc.update("UPDATE adm_mfa_factor SET fail_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                JdbcSupport.timestamp(at), id);
    }

    @Override
    public void deleteByUserId(long userId) {
        jdbc.update("DELETE FROM adm_mfa_factor WHERE user_id = ?", userId);
    }
}
