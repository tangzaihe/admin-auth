package com.aseantec.adminauth.starter.spi;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaFactor;

import java.util.List;
import java.util.Optional;

/**
 * 账号读取 SPI：默认由 JdbcTemplate 仓储备适配，宿主可覆盖以实现"账号来自宿主系统"。
 */
public interface AdminUserProvider {

    Optional<AdminUser> findById(long id);

    /** 按登录标识（原始输入）定位账号：内部完成规范化 + 盲索引。 */
    Optional<AdminUser> findByIdentity(IdentityType type, String rawIdentifier);

    List<AdminIdentity> identitiesOf(long userId);

    List<MfaFactor> activeFactorsOf(long userId);
}
