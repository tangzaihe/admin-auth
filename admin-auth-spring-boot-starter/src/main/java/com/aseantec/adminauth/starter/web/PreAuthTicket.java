package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.LoginStep;

import java.io.Serial;
import java.io.Serializable;

/**
 * 登录中间态票据（pre-auth ticket）。仅存 session，不落库、不下发明文密码。
 * <p>单次消费；TTL 300s（绑定 TOTP 600s）；失败计数用于防爆破。</p>
 */
public class PreAuthTicket implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String value;
    private final long userId;
    private final LoginStep step;
    private final IdentityType identityType;
    private final long expiresAtEpochMillis;
    private int attempts;

    public PreAuthTicket(String value, long userId, LoginStep step, IdentityType identityType,
                         long expiresAtEpochMillis) {
        this.value = value;
        this.userId = userId;
        this.step = step;
        this.identityType = identityType;
        this.expiresAtEpochMillis = expiresAtEpochMillis;
    }

    public String value() {
        return value;
    }

    public long userId() {
        return userId;
    }

    public LoginStep step() {
        return step;
    }

    public IdentityType identityType() {
        return identityType;
    }

    public long expiresAtEpochMillis() {
        return expiresAtEpochMillis;
    }

    public int attempts() {
        return attempts;
    }

    public int incrementAttempts() {
        return ++attempts;
    }

    public boolean expiredAt(long nowEpochMillis) {
        return nowEpochMillis > expiresAtEpochMillis;
    }
}
