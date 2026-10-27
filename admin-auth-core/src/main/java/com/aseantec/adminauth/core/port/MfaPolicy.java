package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaDecision;
import com.aseantec.adminauth.core.domain.MfaFactor;

import java.util.List;

/** 2FA 策略 SPI（默认实现 {@code MfaPolicyService}：四种模式 + 同源禁止 + require-totp-roles）。 */
public interface MfaPolicy {

    MfaDecision decide(AdminUser user, IdentityType loginIdentityType, List<MfaFactor> activeFactors);

    /**
     * 该账号是否被策略"强制"要求 2FA（与是否已绑定无关）。
     * <p>用于阻止用户在强制策略下关闭 2FA；默认 false，宿主自定义策略可覆盖。</p>
     */
    default boolean mandatory(AdminUser user) {
        return false;
    }
}
