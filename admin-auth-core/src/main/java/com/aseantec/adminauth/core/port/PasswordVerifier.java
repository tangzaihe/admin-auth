package com.aseantec.adminauth.core.port;

/** 密码校验 SPI：默认 Starter 提供 BCrypt 实现，宿主可替换。 */
public interface PasswordVerifier {

    String hash(String rawPassword);

    boolean verify(String rawPassword, String encodedPassword);

    /** 算法标识，写入 {@code adm_user.password_algo}。 */
    String algorithm();
}
