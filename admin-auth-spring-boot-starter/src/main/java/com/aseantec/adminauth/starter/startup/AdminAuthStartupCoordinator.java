package com.aseantec.adminauth.starter.startup;

import com.aseantec.adminauth.starter.bootstrap.AdminAuthBootstrapRunner;
import com.aseantec.adminauth.starter.schema.AdminAuthSchemaInitializer;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * 启动编排：在 Web 服务器开始接收请求之前完成 schema 迁移与初始账号创建。
 *
 * <p>使用 {@link SmartInitializingSingleton} 而不是 {@code ApplicationRunner}：
 * 前者在容器单例初始化完成后、Tomcat 启动端口之前执行，避免"服务已监听但表还没建好"的窗口；
 * 多实例并发 bootstrap 由激活标识唯一键兜底。</p>
 */
public class AdminAuthStartupCoordinator implements SmartInitializingSingleton {

    private final AdminAuthSchemaInitializer schemaInitializer;
    private final AdminAuthBootstrapRunner bootstrapRunner;

    public AdminAuthStartupCoordinator(AdminAuthSchemaInitializer schemaInitializer,
                                       AdminAuthBootstrapRunner bootstrapRunner) {
        this.schemaInitializer = schemaInitializer;
        this.bootstrapRunner = bootstrapRunner;
    }

    @Override
    public void afterSingletonsInstantiated() {
        schemaInitializer.initialize();
        bootstrapRunner.initialize();
    }
}
