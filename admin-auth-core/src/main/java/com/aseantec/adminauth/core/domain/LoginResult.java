package com.aseantec.adminauth.core.domain;

import java.util.List;

/** 登录结果：下一步动作 + 命中的账号（账号不存在时为 null）。 */
public record LoginResult(LoginStep step, AdminUser user, List<MfaFactorType> factorTypes) {

    public LoginResult {
        factorTypes = factorTypes == null ? List.of() : List.copyOf(factorTypes);
    }
}
