package com.aseantec.adminauth.core.port;

import java.time.Instant;

/** 时钟 SPI（测试可注入固定时钟）。 */
public interface ClockProvider {

    Instant now();
}
