package com.aseantec.adminauth.starter.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 未认证入口：API 返回 401 JSON，页面 302 到登录页并带 {@code redirect} 参数。
 */
public class AdminAuthEntryPoint implements AuthenticationEntryPoint {

    private final String apiPrefix;
    private final String loginPage;
    private final ObjectMapper objectMapper;

    public AdminAuthEntryPoint(String endpointPrefix, ObjectMapper objectMapper) {
        this.apiPrefix = endpointPrefix + "/api";
        this.loginPage = endpointPrefix + "/login";
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        if (isApiRequest(request)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", "AUTH_FAILED");
            body.put("message", "未登录或会话已过期");
            objectMapper.writeValue(response.getWriter(), body);
            return;
        }
        String target = request.getRequestURI();
        if (request.getQueryString() != null && !request.getQueryString().isBlank()) {
            target += "?" + request.getQueryString();
        }
        String redirect = URLEncoder.encode(target, StandardCharsets.UTF_8).replace("+", "%20");
        response.sendRedirect(loginPage + "?redirect=" + redirect);
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }
        return uri.startsWith(apiPrefix);
    }
}
