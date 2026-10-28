package com.aseantec.adminauth.starter.security;

import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import com.aseantec.adminauth.starter.i18n.BundleAdminAuthMessages;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 未认证入口：API 返回 401 JSON，页面 302 到登录页并带 {@code redirect} 参数。
 *
 * <p><b>i18n</b>：这里在 DispatcherServlet 之前执行，拿不到 MVC 的 {@code Locale}，
 * 因此直接用 {@code Accept-Language} 协商；宿主可通过请求包装或 LocaleResolver 覆盖。</p>
 */
public class AdminAuthEntryPoint implements AuthenticationEntryPoint {

    private static final String CODE = "AUTH_FAILED";
    private static final String MESSAGE_KEY = "admin-auth.error.not-logged-in";

    private final String apiPrefix;
    private final String loginPage;
    private final ObjectMapper objectMapper;
    private final AdminAuthMessages messages;

    public AdminAuthEntryPoint(String endpointPrefix, ObjectMapper objectMapper) {
        this(endpointPrefix, objectMapper, BundleAdminAuthMessages.singleLocale("zh-CN"));
    }

    public AdminAuthEntryPoint(String endpointPrefix, ObjectMapper objectMapper, AdminAuthMessages messages) {
        this.apiPrefix = endpointPrefix + "/api";
        this.loginPage = endpointPrefix + "/login";
        this.objectMapper = objectMapper;
        this.messages = messages;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        if (isApiRequest(request)) {
            Locale locale = messages.resolve(Collections.list(request.getLocales()));
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.setHeader(HttpHeaders.CONTENT_LANGUAGE, locale.toLanguageTag());
            response.setHeader(HttpHeaders.VARY, HttpHeaders.ACCEPT_LANGUAGE);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", CODE);
            body.put("message", messages.message(locale, MESSAGE_KEY));
            body.put("messageKey", MESSAGE_KEY);
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
