package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.MfaFactorType;

/** OTP 发送通道 SPI：v1 无实现（调用 /api/mfa/otp/send 返回 501）。 */
public interface MfaChannelSender {

    MfaFactorType type();

    void send(String destination, String code);
}
