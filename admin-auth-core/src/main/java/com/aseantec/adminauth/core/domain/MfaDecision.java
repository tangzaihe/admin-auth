package com.aseantec.adminauth.core.domain;

import java.util.List;

/**
 * 2FA 策略判定结果。
 *
 * @param required         本次登录是否必须完成 2FA
 * @param bindTotpRequired 是否必须先绑定 TOTP（required 且没有可用因素）
 * @param factorTypes      可选因素类型（按 priority 排序、已做同源过滤）
 */
public record MfaDecision(boolean required, boolean bindTotpRequired, List<MfaFactorType> factorTypes) {

    public MfaDecision {
        factorTypes = factorTypes == null ? List.of() : List.copyOf(factorTypes);
    }

    public static MfaDecision notRequired() {
        return new MfaDecision(false, false, List.of());
    }

    public static MfaDecision bindTotp() {
        return new MfaDecision(true, true, List.of(MfaFactorType.TOTP));
    }

    public boolean selectFactor() {
        return required && !bindTotpRequired && !factorTypes.isEmpty();
    }
}
