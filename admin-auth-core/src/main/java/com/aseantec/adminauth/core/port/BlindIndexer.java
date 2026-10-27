package com.aseantec.adminauth.core.port;

import com.aseantec.adminauth.core.domain.IdentityType;

/** 盲索引 SPI：HMAC-SHA256(indexKey, type|normalized|v1) → 32 字节。 */
public interface BlindIndexer {

    byte[] index(IdentityType type, String normalizedValue);
}
