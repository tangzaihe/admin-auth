package com.aseantec.adminauth.starter.spi;

import com.aseantec.adminauth.core.port.PasswordVerifier;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** 默认密码实现：BCrypt（cost 可配，默认 12），可被宿主 Bean 覆盖。 */
public class BcryptPasswordVerifier implements PasswordVerifier {

    private final BCryptPasswordEncoder encoder;

    public BcryptPasswordVerifier(int cost) {
        this.encoder = new BCryptPasswordEncoder(Math.max(4, cost));
    }

    @Override
    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    @Override
    public boolean verify(String rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }
        try {
            return encoder.matches(rawPassword, encodedPassword);
        } catch (IllegalArgumentException malformedHash) {
            return false;
        }
    }

    @Override
    public String algorithm() {
        return "BCRYPT";
    }
}
