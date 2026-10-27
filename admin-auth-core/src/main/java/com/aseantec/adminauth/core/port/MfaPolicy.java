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
     * 带风险上下文的判定（默认忽略 risk，保持兼容）。
     *
     * @param risk 该账号近期是否有密码失败（用于 {@code ON_RISK} 模式）
     */
    default MfaDecision decide(AdminUser user, IdentityType loginIdentityType,
                               List<MfaFactor> activeFactors, boolean risk) {
        return decide(user, loginIdentityType, activeFactors);
    }

    /**
     * 该账号是否被策略"强制"要求 2FA（与是否已绑定无关）。
     * <p>用于阻止用户在强制策略下关闭 2FA；默认 false，宿主自定义策略可覆盖。</p>
     */
    default boolean mandatory(AdminUser user) {
        return false;
    }
}
