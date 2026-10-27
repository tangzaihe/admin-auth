package com.aseantec.adminauth.starter.jdbc;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.UserStatus;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.Optional;

/** {@code adm_user} 的 JdbcTemplate 实现。 */
public class JdbcAdminUserRepository implements AdminUserRepository {

    private static final String COLUMNS = "id, display_name, role, status, password_hash, password_algo, "
            + "must_change_password, mfa_state, mfa_required, token_version, pwd_updated_at, last_login_at, "
            + "created_at, updated_at";

    private final JdbcTemplate jdbc;

    private final RowMapper<AdminUser> mapper = (rs, rowNum) -> new AdminUser(
            rs.getLong("id"),
            rs.getString("display_name"),
            rs.getString("role"),
            UserStatus.fromCode(rs.getInt("status")),
            rs.getString("password_hash"),
            rs.getString("password_algo"),
            rs.getInt("must_change_password") == 1,
            rs.getInt("mfa_state"),
            rs.getInt("mfa_required"),
            rs.getInt("token_version"),
            JdbcSupport.instant(rs, "pwd_updated_at"),
            JdbcSupport.instant(rs, "last_login_at"),
            JdbcSupport.instant(rs, "created_at"),
            JdbcSupport.instant(rs, "updated_at"));

    public JdbcAdminUserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<AdminUser> findById(long id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_user WHERE id = ?", mapper, id).stream().findFirst();
    }

    @Override
    public long countByRole(String role) {
        Long count = jdbc.queryForObject("SELECT COUNT(*) FROM adm_user WHERE role = ?", Long.class, role);
        return count == null ? 0L : count;
    }

    @Override
    public long countAll() {
        Long count = jdbc.queryForObject("SELECT COUNT(*) FROM adm_user", Long.class);
        return count == null ? 0L : count;
    }

    @Override
    public java.util.List<AdminUser> findPage(int offset, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM adm_user ORDER BY id LIMIT ? OFFSET ?",
                mapper, Math.max(1, limit), Math.max(0, offset));
    }

    @Override
    public long insert(AdminUser user) {
        Instant now = Instant.now();
        return JdbcSupport.insert(jdbc,
                "INSERT INTO adm_user (display_name, role, status, password_hash, password_algo, "
                        + "must_change_password, mfa_state, mfa_required, token_version, pwd_updated_at, "
                        + "last_login_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                user.displayName(),
                user.role(),
                user.status().code(),
                user.passwordHash(),
                user.passwordAlgo(),
                user.mustChangePassword() ? 1 : 0,
                user.mfaState(),
                user.mfaRequired(),
                user.tokenVersion(),
                user.pwdUpdatedAt(),
                user.lastLoginAt(),
                JdbcSupport.instantOrNow(user.createdAt() == null ? now : user.createdAt()),
                JdbcSupport.instantOrNow(user.updatedAt() == null ? now : user.updatedAt()));
    }

    @Override
    public void updatePassword(long id, String passwordHash, String passwordAlgo, Instant pwdUpdatedAt,
                               boolean mustChangePassword) {
        jdbc.update("UPDATE adm_user SET password_hash = ?, password_algo = ?, must_change_password = ?, "
                        + "pwd_updated_at = ?, token_version = token_version + 1, updated_at = ? WHERE id = ?",
                passwordHash, passwordAlgo, mustChangePassword ? 1 : 0, JdbcSupport.timestamp(pwdUpdatedAt),
                JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateLastLogin(long id, Instant at) {
        jdbc.update("UPDATE adm_user SET last_login_at = ?, updated_at = ? WHERE id = ?",
                JdbcSupport.timestamp(at), JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateMfaState(long id, int mfaState) {
        jdbc.update("UPDATE adm_user SET mfa_state = ?, updated_at = ? WHERE id = ?",
                mfaState, JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateMfaRequired(long id, int mfaRequired) {
        jdbc.update("UPDATE adm_user SET mfa_required = ?, updated_at = ? WHERE id = ?",
                mfaRequired, JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public void updateStatus(long id, UserStatus status) {
        jdbc.update("UPDATE adm_user SET status = ?, updated_at = ? WHERE id = ?",
                status.code(), JdbcSupport.timestamp(Instant.now()), id);
    }

    @Override
    public int incrementTokenVersion(long id) {
        jdbc.update("UPDATE adm_user SET token_version = token_version + 1, updated_at = ? WHERE id = ?",
                JdbcSupport.timestamp(Instant.now()), id);
        Integer version = jdbc.queryForObject("SELECT token_version FROM adm_user WHERE id = ?", Integer.class, id);
        return version == null ? 0 : version;
    }
}
