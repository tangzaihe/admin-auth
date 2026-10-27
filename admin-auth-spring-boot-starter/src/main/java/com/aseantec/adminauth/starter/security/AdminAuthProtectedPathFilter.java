package com.aseantec.adminauth.starter.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * FILTER_ONLY 模式：用普通 Servlet Filter 保护 {@code admin-auth.protected-paths}。
 * <p>不依赖 Spring Security 链，未登录时走 EntryPoint（API 401 / 页面 302）。</p>
 */
public class AdminAuthProtectedPathFilter extends OncePerRequestFilter {

    private final List<String> protectedPaths;
    private final AdminSessionService sessions;
    private final AdminAuthEntryPoint entryPoint;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public AdminAuthProtectedPathFilter(List<String> protectedPaths,
                                        AdminSessionService sessions,
                                        AdminAuthEntryPoint entryPoint) {
        this.protectedPaths = protectedPaths == null ? List.of() : List.copyOf(protectedPaths);
        this.sessions = sessions;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        String path = (context != null && !context.isEmpty() && uri.startsWith(context))
                ? uri.substring(context.length())
                : uri;
        boolean matches = protectedPaths.stream().anyMatch(pattern -> matcher.match(pattern, path));
        if (matches && sessions.current(request) == null) {
            entryPoint.commence(request, response,
                    new InsufficientAuthenticationException("未登录或会话已过期"));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
