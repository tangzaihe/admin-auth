package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.FactorStatus;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaDecision;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import com.aseantec.adminauth.core.domain.MfaPolicyMode;
import com.aseantec.adminauth.core.domain.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** 2FA 策略矩阵：四种模式 × 用户级覆盖 × 同源禁止 × require-totp-roles × priority 排序。 */
class MfaPolicyServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");

    @Test
    @DisplayName("OFF：即使已绑定因素也不要求")
    void offNeverRequires() {
        MfaPolicyService policy = policy(MfaPolicyMode.OFF, Set.of(), Set.of(), true);
        MfaDecision decision = policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of(totp()));
        assertThat(decision.required()).isFalse();
        assertThat(decision.factorTypes()).isEmpty();
    }

    @Test
    @DisplayName("OPTIONAL：未绑定不要求；已绑定 TOTP 则要求")
    void optionalRequiresOnlyWhenBound() {
        MfaPolicyService policy = policy(MfaPolicyMode.OPTIONAL, Set.of(), Set.of(), true);
        assertThat(policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of()).required()).isFalse();

        MfaDecision bound = policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of(totp()));
        assertThat(bound.required()).isTrue();
        assertThat(bound.factorTypes()).containsExactly(MfaFactorType.TOTP);
    }

    @Test
    @DisplayName("REQUIRED_BY_ROLE：命中角色必须绑定；未命中且无因素不要求")
    void requiredByRole() {
        MfaPolicyService policy = policy(MfaPolicyMode.REQUIRED_BY_ROLE, Set.of("SUPER_ADMIN"), Set.of(), true);

        MfaDecision admin = policy.decide(user("SUPER_ADMIN", -1), IdentityType.EMAIL, List.of());
        assertThat(admin.required()).isTrue();
        assertThat(admin.bindTotpRequired()).isTrue();

        MfaDecision viewer = policy.decide(user("VIEWER", -1), IdentityType.EMAIL, List.of());
        assertThat(viewer.required()).isFalse();
    }

    @Test
    @DisplayName("REQUIRED_ALL：无因素要求绑定；有 TOTP 要求校验")
    void requiredAll() {
        MfaPolicyService policy = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(), Set.of(), true);
        assertThat(policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of()).bindTotpRequired()).isTrue();

        MfaDecision decision = policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of(totp()));
        assertThat(decision.selectFactor()).isTrue();
        assertThat(decision.factorTypes()).containsExactly(MfaFactorType.TOTP);
    }

    @Test
    @DisplayName("用户级覆盖优先：mfa_required=1 覆盖 OFF；mfa_required=0 覆盖 REQUIRED_ALL")
    void userOverrideWins() {
        MfaPolicyService off = policy(MfaPolicyMode.OFF, Set.of(), Set.of(), true);
        assertThat(off.decide(user("ADMIN", 1), IdentityType.EMAIL, List.of()).required()).isTrue();

        MfaPolicyService requiredAll = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(), Set.of(), true);
        assertThat(requiredAll.decide(user("ADMIN", 0), IdentityType.EMAIL, List.of(totp())).required()).isFalse();
    }

    @Test
    @DisplayName("同源禁止：EMAIL 登录剔除 EMAIL_OTP；PHONE 登录剔除 SMS_OTP；关闭开关后允许")
    void forbidSameChannel() {
        MfaPolicyService policy = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(), Set.of(), true);

        MfaDecision email = policy.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of(emailOtp()));
        assertThat(email.bindTotpRequired()).isTrue();

        MfaDecision phone = policy.decide(user("ADMIN", -1), IdentityType.PHONE, List.of(smsOtp()));
        assertThat(phone.bindTotpRequired()).isTrue();

        MfaDecision staffCode = policy.decide(user("ADMIN", -1), IdentityType.STAFF_CODE, List.of(emailOtp(), smsOtp()));
        assertThat(staffCode.factorTypes()).containsExactly(MfaFactorType.SMS_OTP, MfaFactorType.EMAIL_OTP);

        MfaPolicyService lenient = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(), Set.of(), false);
        MfaDecision allowed = lenient.decide(user("ADMIN", -1), IdentityType.EMAIL, List.of(emailOtp()));
        assertThat(allowed.factorTypes()).containsExactly(MfaFactorType.EMAIL_OTP);
    }

    @Test
    @DisplayName("require-totp-roles：命中角色只允许 TOTP，即使已绑定 OTP")
    void requireTotpRoles() {
        MfaPolicyService policy = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(),
                Set.of("SUPER_ADMIN"), true);

        MfaDecision decision = policy.decide(user("SUPER_ADMIN", -1), IdentityType.STAFF_CODE,
                List.of(emailOtp(), totp()));
        assertThat(decision.factorTypes()).containsExactly(MfaFactorType.TOTP);

        MfaDecision noTotp = policy.decide(user("SUPER_ADMIN", -1), IdentityType.STAFF_CODE,
                List.of(emailOtp()));
        assertThat(noTotp.bindTotpRequired()).isTrue();
    }

    @Test
    @DisplayName("多因素按 priority 升序返回；非 ACTIVE 因素被忽略")
    void priorityAndStatus() {
        MfaPolicyService policy = policy(MfaPolicyMode.REQUIRED_ALL, Set.of(), Set.of(), true);
        MfaFactor sms = factor(2L, MfaFactorType.SMS_OTP, 20, FactorStatus.ACTIVE);
        MfaFactor totp = factor(1L, MfaFactorType.TOTP, 10, FactorStatus.ACTIVE);
        MfaFactor pending = factor(3L, MfaFactorType.EMAIL_OTP, 5, FactorStatus.PENDING);

        MfaDecision decision = policy.decide(user("ADMIN", -1), IdentityType.STAFF_CODE,
                List.of(sms, totp, pending));
        assertThat(decision.factorTypes()).containsExactly(MfaFactorType.TOTP, MfaFactorType.SMS_OTP);
    }

    // ---------- fixtures ----------

    private MfaPolicyService policy(MfaPolicyMode mode, Set<String> requiredRoles,
                                    Set<String> requireTotpRoles, boolean forbidSameChannel) {
        return new MfaPolicyService(mode, requiredRoles, requireTotpRoles, forbidSameChannel);
    }

    private AdminUser user(String role, int mfaRequired) {
        return new AdminUser(1L, "测试用户", role, UserStatus.ACTIVE, "hash", "BCRYPT",
                false, 0, mfaRequired, 0, null, null, NOW, NOW);
    }

    private MfaFactor totp() {
        return factor(1L, MfaFactorType.TOTP, 10, FactorStatus.ACTIVE);
    }

    private MfaFactor emailOtp() {
        return factor(2L, MfaFactorType.EMAIL_OTP, 30, FactorStatus.ACTIVE);
    }

    private MfaFactor smsOtp() {
        return factor(3L, MfaFactorType.SMS_OTP, 20, FactorStatus.ACTIVE);
    }

    private MfaFactor factor(long id, MfaFactorType type, int priority, FactorStatus status) {
        return new MfaFactor(id, 1L, type, 0L, null, 1, 6, 30, 0L, null, priority, null, 0, null, status);
    }
}
