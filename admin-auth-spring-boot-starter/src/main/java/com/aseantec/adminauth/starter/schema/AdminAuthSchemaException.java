package com.aseantec.adminauth.starter.schema;

import com.aseantec.adminauth.starter.config.SchemaMode;

/**
 * schema 初始化失败（连接不上数据库、迁移校验不通过等）。
 * <p>由 {@link AdminAuthSchemaFailureAnalyzer} 转成精简的启动失败提示，避免刷屏堆栈。</p>
 */
public class AdminAuthSchemaException extends RuntimeException {

    private final SchemaMode mode;

    public AdminAuthSchemaException(SchemaMode mode, String reason, Throwable cause) {
        super(reason, cause);
        this.mode = mode;
    }

    public SchemaMode mode() {
        return mode;
    }
}
