package com.aseantec.adminauth.starter.security;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;

import java.time.Instant;
import java.util.List;

/**
 * 会话服务：登录成功写入会话、读取当前主体、强制下线、失效。
 *
 * <p><b>写入内容</b>（第 5 段约定）：{@code ADM_PRINCIPAL}（Serializable 主体）、
 * {@code PRINCIPAL_NAME_INDEX_NAME}（= userId，供 Spring Session 建索引）、
 * {@code SPRING_SECURITY_CONTEXT}（兼容宿主 Security）。</p>
 *
 * <p><b>链路</b>：登录/2FA 成功 → changeSessionId（防会话固定）→ 清空 pre-auth ticket
 * → 写主体 → 记录绝对过期时间；改密/停用/重置时按 principal name 删除全部会话。</p>
 */
public class AdminSessionService {

    public static final String ATTR_PRINCIPAL = "ADM_PRINCIPAL";
    public static final String ATTR_PRINCIPAL_NAME = FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;
    public static final String ATTR_SECURITY_CONTEXT = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

    private final ClockProvider clock;
    private final AdminAuthProperties properties;
    private final JdbcTemplate jdbc;
    private final ObjectProvider<JdbcIndexedSessionRepository> sessionRepository;

    public AdminSessionService(ClockProvider clock,
                               AdminAuthProperties properties,
                               JdbcTemplate jdbc,
                               ObjectProvider<JdbcIndexedSessionRepository> sessionRepository) {
        this.clock = clock;
        this.properties = properties;
        this.jdbc = jdbc;
        this.sessionRepository = sessionRepository;
    }

    /** 登录成功：切换 sessionId 并写入主体，返回新建的主体。 */
    public AdminSessionPrincipal establish(HttpServletRequest request, AdminUser user, boolean mfaVerified) {
        HttpSession session = request.getSession(true);
        request.changeSessionId();
        session.removeAttribute(com.aseantec.adminauth.starter.web.PreAuthTicketService.SESSION_KEY);

        Instant now = clock.now();
        Instant absoluteExpireAt = now.plus(properties.getSession().getAbsolute());
        AdminSessionPrincipal principal = new AdminSessionPrincipal(
                user.id(), user.displayName(), user.role(), mfaVerified, now, absoluteExpireAt,
                mfaVerified ? now : null);

        session.setAttribute(ATTR_PRINCIPAL, principal);
        session.setAttribute(ATTR_PRINCIPAL_NAME, String.valueOf(user.id()));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                principal, null, List.of(new SimpleGrantedAuthority("ROLE_" + user.role()))));
        session.setAttribute(ATTR_SECURITY_CONTEXT, context);
        SecurityContextHolder.setContext(context);
        return principal;
    }

    /** 读取当前主体（无会话返回 null，不抛异常）。 */
    public AdminSessionPrincipal current(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object attribute = session.getAttribute(ATTR_PRINCIPAL);
        return attribute instanceof AdminSessionPrincipal principal ? principal : null;
    }

    /** 注销：失效当前会话并清理上下文。 */
    public void invalidate(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            try {
                session.invalidate();
            } catch (IllegalStateException alreadyInvalidated) {
                // 已失效，忽略
            }
        }
        SecurityContextHolder.clearContext();
    }

    /** 删除某账号的全部会话（改密/停用/管理员重置 2FA 时调用）。 */
    public void deleteAllSessionsOf(long userId) {
        String principalName = String.valueOf(userId);
        JdbcIndexedSessionRepository repository = sessionRepository.getIfAvailable();
        if (repository != null) {
            repository.findByPrincipalName(principalName).keySet().forEach(repository::deleteById);
            return;
        }
        try {
            jdbc.update("DELETE FROM ADM_SESSION WHERE PRINCIPAL_NAME = ?", principalName);
        } catch (RuntimeException e) {
            // 未启用 Spring Session JDBC 时无会话表，属正常情况
        }
    }
}
