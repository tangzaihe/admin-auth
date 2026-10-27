package com.aseantec.adminauth.starter.security;

import com.aseantec.adminauth.core.port.ClockProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * 会话上下文过滤器：把 session 中的 {@link AdminSessionPrincipal} 还原成
 * Spring Security {@code Authentication}，并强制"绝对 8h 过期"。
 *
 * <p>ISOLATED 模式下挂在 SecurityContextHolderFilter 之后；INTEGRATED/FILTER_ONLY
 * 模式由宿主或 Servlet 过滤器注册使用。</p>
 */
public class AdminSessionAuthenticationFilter extends OncePerRequestFilter {

    private final ClockProvider clock;

    public AdminSessionAuthenticationFilter(ClockProvider clock) {
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object attribute = session.getAttribute(AdminSessionService.ATTR_PRINCIPAL);
            if (attribute instanceof AdminSessionPrincipal principal) {
                if (principal.absoluteExpireAt() != null && principal.absoluteExpireAt().isBefore(clock.now())) {
                    // 绝对有效期到点：直接失效，不续期
                    session.invalidate();
                    SecurityContextHolder.clearContext();
                } else if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                            principal, null, List.of(new SimpleGrantedAuthority("ROLE_" + principal.role()))));
                    SecurityContextHolder.setContext(context);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
