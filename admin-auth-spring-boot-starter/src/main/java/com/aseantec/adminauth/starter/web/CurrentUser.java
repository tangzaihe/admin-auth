package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.starter.security.AdminSessionPrincipal;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import jakarta.servlet.http.HttpServletRequest;

/** 当前登录主体快捷读取（控制器与服务共用）。 */
public final class CurrentUser {

    private CurrentUser() {
    }

    public static AdminSessionPrincipal require(HttpServletRequest request, AdminSessionService sessions) {
        AdminSessionPrincipal principal = sessions.current(request);
        if (principal == null) {
            throw new ApiException(ApiErrorCode.AUTH_FAILED, "admin-auth.error.not-logged-in");
        }
        return principal;
    }

    /** 客户端 IP：默认不信任 X-Forwarded-For，避免伪造绕过限速。 */
    public static String ip(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        return remote == null ? "" : remote;
    }

    public static String userAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return ua == null ? "" : (ua.length() > 255 ? ua.substring(0, 255) : ua);
    }
}
