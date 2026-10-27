package com.aseantec.adminauth.core.domain;

/**
 * 2FA 策略模式。
 * <ul>
 *   <li>{@link #OFF}：从不要求 2FA；</li>
 *   <li>{@link #ON_RISK}：仅当该账号近期有密码失败时要求（且需已绑定因素），平时只验密码；</li>
 *   <li>{@link #OPTIONAL}：用户已绑定因素即要求（绑定即视为主动开启）；</li>
 *   <li>{@link #REQUIRED_BY_ROLE}：角色命中 required-roles 即要求（已绑定因素同样要求）；</li>
 *   <li>{@link #REQUIRED_ALL}：所有账号均要求。</li>
 * </ul>
 * 用户级覆盖 {@code adm_user.mfa_required}（-1 继承 / 0 强制关闭 / 1 强制开启）优先级最高。
 */
public enum MfaPolicyMode {
    OFF,
    ON_RISK,
    OPTIONAL,
    REQUIRED_BY_ROLE,
    REQUIRED_ALL
}
