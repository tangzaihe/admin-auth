package com.aseantec.adminauth.starter.bootstrap;

import com.aseantec.adminauth.starter.admin.AdminAuthUserAdminService;

/**
 * 启动引导：无初始管理员时按配置创建（幂等）。
 *
 * <p>具体创建逻辑（账号 + EMAIL/STAFF_CODE 标识 + 审计）在 {@link AdminAuthUserAdminService}，
 * 由 {@code AdminAuthStartupCoordinator} 在 Web 端口监听前调用。</p>
 */
public class AdminAuthBootstrapRunner {

    private final AdminAuthUserAdminService userAdminService;

    public AdminAuthBootstrapRunner(AdminAuthUserAdminService userAdminService) {
        this.userAdminService = userAdminService;
    }

    public void initialize() {
        userAdminService.bootstrapAdminIfMissing();
    }
}
