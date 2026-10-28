package com.aseantec.adminauth.starter.security;

import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import com.aseantec.adminauth.starter.i18n.BundleAdminAuthMessages;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** 已登录但无权限：API 返回 403 JSON，页面返回 403。 */
public class AdminAuthAccessDeniedHandler implements AccessDeniedHandler {

    private static final String CODE = "FORBIDDEN";
    private static final String MESSAGE_KEY = "admin-auth.error.forbidden";

    private final String apiPrefix;
    private final ObjectMapper objectMapper;
    private final AdminAuthMessages messages;

    public AdminAuthAccessDeniedHandler(String endpointPrefix, ObjectMapper objectMapper) {
        this(endpointPrefix, objectMapper, BundleAdminAuthMessages.singleLocale("zh-CN"));
    }

    public AdminAuthAccessDeniedHandler(String endpointPrefix, ObjectMapper objectMapper,
                                        AdminAuthMessages messages) {
        this.apiPrefix = endpointPrefix + "/api";
        this.objectMapper = objectMapper;
        this.messages = messages;
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
            Locale locale = messages.resolve(Collections.list(request.getLocales()));
            response.setContentType("application/json;charset=UTF-8");
            response.setHeader(HttpHeaders.CONTENT_LANGUAGE, locale.toLanguageTag());
            response.setHeader(HttpHeaders.VARY, HttpHeaders.ACCEPT_LANGUAGE);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", CODE);
            body.put("message", messages.message(locale, MESSAGE_KEY));
            body.put("messageKey", MESSAGE_KEY);
            objectMapper.writeValue(response.getWriter(), body);
        } else {
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("403 Forbidden");
        }
    }
}
