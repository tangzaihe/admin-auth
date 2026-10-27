package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.IdentityType;

/** 标识规范化 SPI（EMAIL 小写 / PHONE 去分隔符 / STAFF_CODE 大写）。 */
public interface IdentityNormalizer {

    String normalize(IdentityType type, String raw);
}
