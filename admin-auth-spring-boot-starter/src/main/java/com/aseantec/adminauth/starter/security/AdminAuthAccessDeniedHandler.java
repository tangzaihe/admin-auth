package com.aseantec.adminauth.starter.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** 已登录但无权限：API 返回 403 JSON，页面返回 403。 */
public class AdminAuthAccessDeniedHandler implements AccessDeniedHandler {

    private final String apiPrefix;
    private final ObjectMapper objectMapper;

    public AdminAuthAccessDeniedHandler(String endpointPrefix, ObjectMapper objectMapper) {
        this.apiPrefix = endpointPrefix + "/api";
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }
        if (uri.startsWith(apiPrefix)) {
            response.setContentType("application/json;charset=UTF-8");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", "FORBIDDEN");
            body.put("message", "无权访问");
            objectMapper.writeValue(response.getWriter(), body);
        } else {
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("403 Forbidden");
        }
    }
}
