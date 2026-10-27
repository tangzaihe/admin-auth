package com.aseantec.adminauth.sample;

import com.aseantec.adminauth.starter.security.AdminSessionPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** 示例业务接口：/ 公开，/admin/hello 由保护路径拦截，必须是登录态。 */
@RestController
public class SampleController {

    @GetMapping("/")
    public Map<String, Object> root() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "public ok");
        body.put("loginPage", "/admin-auth/login");
        body.put("protected", "/admin/hello");
        return body;
    }

    @GetMapping("/admin/hello")
    public Map<String, Object> hello(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        Object attribute = session == null ? null : session.getAttribute("ADM_PRINCIPAL");
        if (!(attribute instanceof AdminSessionPrincipal principal)) {
            // 正常不会走到这里：Security 链已在入口处返回 401/302
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("message", "not authenticated");
            return body;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "hello, admin");
        body.put("userId", principal.userId());
        body.put("displayName", principal.displayName());
        body.put("role", principal.role());
        body.put("mfaVerified", principal.mfaVerified());
        body.put("authenticatedAt", principal.authenticatedAt().toString());
        return body;
    }
}
