package com.aseantec.adminauth.starter.config;

/** schema 管理模式：off=不管理（demo 由 spring.sql.init 建表）/ auto=自动迁移 / validate=只校验并 fail-fast。 */
public enum SchemaMode {
    OFF,
    AUTO,
    VALIDATE
}
