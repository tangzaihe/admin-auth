package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.UserStatus;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** 账号主体仓储端口（starter 用 JdbcTemplate 实现）。 */
public interface AdminUserRepository {

    Optional<AdminUser> findById(long id);

    long countByRole(String role);

    long countAll();

    /** 分页查询（管理台列表），按 id 升序。 */
    List<AdminUser> findPage(int offset, int limit);

    long insert(AdminUser user);

    /** 改密/重置密码：同时 token_version+1。 */
    void updatePassword(long id, String passwordHash, String passwordAlgo, Instant pwdUpdatedAt, boolean mustChangePassword);

    void updateLastLogin(long id, Instant at);

    void updateMfaState(long id, int mfaState);

    void updateMfaRequired(long id, int mfaRequired);

    void updateStatus(long id, UserStatus status);

    int incrementTokenVersion(long id);
}
