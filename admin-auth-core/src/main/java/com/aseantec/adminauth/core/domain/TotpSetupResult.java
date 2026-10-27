package com.aseantec.adminauth.core.domain;

/** TOTP 绑定初始化结果（明文 secret 只在内存与本次响应中出现，不落库）。 */
public record TotpSetupResult(String manualSecret, String otpauthUri) {
}
