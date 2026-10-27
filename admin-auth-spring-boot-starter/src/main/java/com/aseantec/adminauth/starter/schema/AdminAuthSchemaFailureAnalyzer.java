package com.aseantec.adminauth.starter.schema;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/** 把 schema 初始化异常转成一段可执行的启动失败提示（APPLICATION FAILED TO START）。 */
public class AdminAuthSchemaFailureAnalyzer extends AbstractFailureAnalyzer<AdminAuthSchemaException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, AdminAuthSchemaException cause) {
        String description = "admin-auth 数据库初始化失败（schema.mode=" + cause.mode() + "）：" + cause.getMessage();
        String action = "请确认 spring.datasource.url / username / password 可连接、目标库已创建；"
                + "本机没有 MySQL 时可用 H2 demo 启动：--spring.profiles.active=demo；"
                + "若建表由发布流程负责，请设置 admin-auth.schema.mode=validate。";
        return new FailureAnalysis(description, action, cause);
    }
}
