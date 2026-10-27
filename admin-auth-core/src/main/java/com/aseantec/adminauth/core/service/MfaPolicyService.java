package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaDecision;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import com.aseantec.adminauth.core.domain.MfaPolicyMode;
import com.aseantec.adminauth.core.port.MfaPolicy;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 默认 2FA 策略实现：四种模式 + 用户级覆盖 + 同源禁止 + require-totp-roles。
 *
 * <p><b>判定链路</b></p>
 * <ol>
 *   <li>用户级 {@code mfa_required}（-1/0/1）优先于全局模式；</li>
 *   <li>按模式判定是否必须 2FA；</li>
 *   <li>过滤可用因素：仅 ACTIVE → require-totp-roles 只留 TOTP → 同源禁止剔除同通道 OTP；</li>
 *   <li>无可用因素 → 要求先绑定 TOTP（{@link MfaDecision#bindTotp()}）。</li>
 * </ol>
 */
public class MfaPolicyService implements MfaPolicy {

    private final MfaPolicyMode mode;
    private final Set<String> requiredRoles;
    private final Set<String> requireTotpRoles;
    private final boolean forbidSameChannel;

    public MfaPolicyService(MfaPolicyMode mode,
                            Set<String> requiredRoles,
                            Set<String> requireTotpRoles,
                            boolean forbidSameChannel) {
        this.mode = mode == null ? MfaPolicyMode.OPTIONAL : mode;
        this.requiredRoles = normalizeRoles(requiredRoles);
        this.requireTotpRoles = normalizeRoles(requireTotpRoles);
        this.forbidSameChannel = forbidSameChannel;
    }

    @Override
    public MfaDecision decide(AdminUser user, IdentityType loginIdentityType, List<MfaFactor> activeFactors) {
        return decide(user, loginIdentityType, activeFactors, false);
    }

    @Override
    public MfaDecision decide(AdminUser user, IdentityType loginIdentityType,
                              List<MfaFactor> activeFactors, boolean risk) {
        List<MfaFactor> factors = activeFactors == null ? List.of() : activeFactors;
        if (!required(user, factors, risk)) {
            return MfaDecision.notRequired();
        }
        List<MfaFactor> eligible = new ArrayList<>();
        for (MfaFactor factor : factors) {
            if (!factor.active()) {
                continue;
            }
            if (requireTotpRoles.contains(user.role()) && factor.factorType() != MfaFactorType.TOTP) {
                continue;
            }
            if (forbidSameChannel && factor.factorType().sameChannelAs(loginIdentityType)) {
                continue;
            }
            eligible.add(factor);
        }
        if (eligible.isEmpty()) {
            return MfaDecision.bindTotp();
        }
        eligible.sort(Comparator.comparingInt(MfaFactor::priority));
        Set<MfaFactorType> types = new LinkedHashSet<>();
        for (MfaFactor factor : eligible) {
            types.add(factor.factorType());
        }
        return new MfaDecision(true, false, List.copyOf(types));
    }

    /** 用户是否需要 2FA（含用户级覆盖）。 */
    public boolean required(AdminUser user, List<MfaFactor> factors) {
        return required(user, factors, false);
    }

    /** 用户是否需要 2FA（含用户级覆盖与风险标记）。 */
    public boolean required(AdminUser user, List<MfaFactor> factors, boolean risk) {
        if (user.mfaRequired() == 0) {
            return false;
        }
        if (user.mfaRequired() == 1) {
            return true;
        }
        boolean hasActiveFactor = factors != null && factors.stream().anyMatch(MfaFactor::active);
        return switch (mode) {
            case OFF -> false;
            // 风险触发：只有近期密码失败且已绑定因素时才要求；未绑定则跳过（避免因输错一次密码被迫绑定）
            case ON_RISK -> risk && hasActiveFactor;
            case OPTIONAL -> hasActiveFactor;
            case REQUIRED_BY_ROLE -> requiredRoles.contains(user.role()) || hasActiveFactor;
            case REQUIRED_ALL -> true;
        };
    }

    /** 策略是否强制该账号启用 2FA（与已绑定无关）：用于阻止强制策略下关闭 2FA。 */
    @Override
    public boolean mandatory(AdminUser user) {
        if (user.mfaRequired() == 0) {
            return false;
        }
        if (user.mfaRequired() == 1) {
            return true;
        }
        return switch (mode) {
            // ON_RISK 不强制绑定/启用，只做风险触发
            case OFF, OPTIONAL, ON_RISK -> false;
            case REQUIRED_BY_ROLE -> requiredRoles.contains(user.role());
            case REQUIRED_ALL -> true;
        };
    }

    public MfaPolicyMode mode() {
        return mode;
    }

    private Set<String> normalizeRoles(Set<String> roles) {
        Set<String> normalized = new LinkedHashSet<>();
        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    normalized.add(role.trim().toUpperCase(Locale.ROOT));
                }
            }
        }
        return normalized;
    }
}
