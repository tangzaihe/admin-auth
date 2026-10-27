package com.aseantec.adminauth.starter.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 内置页面（外壳 + 原生 JS，数据全部走 /api/**）。
 * <p>页面本身不需要登录态：数据接口会返回 401，前端据此跳转登录页。</p>
 */
@Controller
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}")
public class AdminAuthPageController {

    @GetMapping({"/", "", "/login"})
    public String login() {
        return "admin-auth/login";
    }

    @GetMapping("/2fa")
    public String twoFactor() {
        return "admin-auth/2fa";
    }

    @GetMapping("/totp-setup")
    public String totpSetup() {
        return "admin-auth/totp-setup";
    }

    @GetMapping("/password-change")
    public String passwordChange() {
        return "admin-auth/password-change";
    }

    @GetMapping("/recovery-codes")
    public String recoveryCodes() {
        return "admin-auth/recovery-codes";
    }
}
