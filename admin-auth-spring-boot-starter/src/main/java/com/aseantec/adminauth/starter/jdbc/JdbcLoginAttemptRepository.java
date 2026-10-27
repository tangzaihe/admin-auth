package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.LoginAttempt;
import com.aseantec.adminauth.core.port.LoginAttemptRepository;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * {@code adm_login_attempt} 的 JdbcTemplate 实现。
 * <p>唯一键 (identity_hash, ip) 保护并发；命中账号后回填 user_id，user 维度用 SUM(fail_count) 合并计数。
 * 不使用 MySQL 专有 ON DUPLICATE KEY（H2 兼容，第 8 段坑 ⑫）。</p>
 */
public class JdbcLoginAttemptRepository implements LoginAttemptRepository {

    private static final String COLUMNS = "id, user_id, identity_hash, ip, fail_count, locked_until, updated_at";

    private final JdbcTemplate jdbc;

    private final RowMapper<LoginAttempt> mapper = (rs, rowNum) -> new LoginAttempt(
            rs.getLong("id"),
            (Long) rs.getObject("user_id"),
            rs.getBytes("identity_hash"),
            rs.getString("ip"),
            rs.getInt("fail_count"),
            JdbcSupport.instant(rs, "locked_until"),
            JdbcSupport.instant(rs, "updated_at"));

    public JdbcLoginAttemptRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<LoginAttempt> findByIdentityHashAndIp(byte[] identityHash, String ip) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_login_attempt WHERE identity_hash = ? AND ip = ?",
                mapper, identityHash, ip).stream().findFirst();
    }

    @Override
    public int incrementAndGet(byte[] identityHash, String ip, Long userId, Instant now) {
        int updated = userId == null
                ? jdbc.update("UPDATE adm_login_attempt SET fail_count = fail_count + 1, updated_at = ? "
                        + "WHERE identity_hash = ? AND ip = ?", JdbcSupport.timestamp(now), identityHash, ip)
                : jdbc.update("UPDATE adm_login_attempt SET fail_count = fail_count + 1, user_id = ?, updated_at = ? "
                        + "WHERE identity_hash = ? AND ip = ?", userId, JdbcSupport.timestamp(now), identityHash, ip);
        if (updated == 0) {
            try {
                jdbc.update("INSERT INTO adm_login_attempt (user_id, identity_hash, ip, fail_count, updated_at) "
                        + "VALUES (?,?,?,1,?)", userId, identityHash, ip, JdbcSupport.timestamp(now));
            } catch (DuplicateKeyException race) {
                jdbc.update("UPDATE adm_login_attempt SET fail_count = fail_count + 1, updated_at = ? "
                        + "WHERE identity_hash = ? AND ip = ?", JdbcSupport.timestamp(now), identityHash, ip);
            }
        }
        Integer count = jdbc.queryForObject(
                "SELECT fail_count FROM adm_login_attempt WHERE identity_hash = ? AND ip = ?",
                Integer.class, identityHash, ip);
        return count == null ? 1 : count;
    }

    @Override
    public Optional<Instant> findLockedUntil(byte[] identityHash, String ip) {
        List<Timestamp> rows = jdbc.query(
                "SELECT locked_until FROM adm_login_attempt WHERE identity_hash = ? AND ip = ?",
                (rs, rowNum) -> rs.getTimestamp(1), identityHash, ip);
        return rows.stream().filter(java.util.Objects::nonNull).findFirst().map(Timestamp::toInstant);
    }

    @Override
    public void setLockedUntil(byte[] identityHash, String ip, Instant until) {
        jdbc.update("UPDATE adm_login_attempt SET locked_until = ?, updated_at = ? WHERE identity_hash = ? AND ip = ?",
                JdbcSupport.timestamp(until), JdbcSupport.timestamp(Instant.now()), identityHash, ip);
    }

    @Override
    public void clear(byte[] identityHash, String ip) {
        jdbc.update("DELETE FROM adm_login_attempt WHERE identity_hash = ? AND ip = ?", identityHash, ip);
    }

    @Override
    public Optional<Instant> findUserLockedUntil(long userId, String ip) {
        List<Timestamp> rows = jdbc.query(
                "SELECT MAX(locked_until) FROM adm_login_attempt WHERE user_id = ? AND ip = ?",
                (rs, rowNum) -> rs.getTimestamp(1), userId, ip);
        return rows.stream().filter(java.util.Objects::nonNull).findFirst().map(Timestamp::toInstant);
    }

    @Override
    public int sumUserFailures(long userId, String ip) {
        Integer sum = jdbc.queryForObject(
                "SELECT COALESCE(SUM(fail_count), 0) FROM adm_login_attempt WHERE user_id = ? AND ip = ?",
                Integer.class, userId, ip);
        return sum == null ? 0 : sum;
    }

    @Override
    public void clearUser(long userId, String ip) {
        jdbc.update("DELETE FROM adm_login_attempt WHERE user_id = ? AND ip = ?", userId, ip);
    }

    @Override
    public void clearAllForUser(long userId) {
        jdbc.update("DELETE FROM adm_login_attempt WHERE user_id = ?", userId);
    }

    @Override
    public void lockUser(long userId, String ip, Instant until) {
        jdbc.update("UPDATE adm_login_attempt SET locked_until = ?, updated_at = ? WHERE user_id = ? AND ip = ?",
                JdbcSupport.timestamp(until), JdbcSupport.timestamp(Instant.now()), userId, ip);
    }
}
