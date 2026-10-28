package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.LoginStep;
import com.aseantec.adminauth.core.port.ClockProvider;
import jakarta.servlet.http.HttpSession;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * pre-auth ticket 管理：32B 随机 Base64Url 存 session，单次消费。
 *
 * <p><b>链路</b>：登录返回下一步（改密/绑定/选因素）时签发 → 后续请求校验并取出 userId
 * → 成功后消费；失败累计 5 次则作废并返回 423。</p>
 */
public class PreAuthTicketService {

    public static final String SESSION_KEY = "ADM_PRE_AUTH_TICKETS";

    private static final int TTL_SECONDS = 300;
    private static final int BIND_TTL_SECONDS = 600;
    private static final int MAX_ATTEMPTS = 5;

    private final SecureRandom random = new SecureRandom();
    private final ClockProvider clock;

    public PreAuthTicketService(ClockProvider clock) {
        this.clock = clock;
    }

    /** 签发新 ticket（旧 ticket 保留直到过期，避免并发请求互相踢掉）。 */
    public String issue(HttpSession session, long userId, LoginStep step, IdentityType identityType) {
        Map<String, PreAuthTicket> tickets = tickets(session);
        long now = clock.now().toEpochMilli();
        tickets.entrySet().removeIf(entry -> entry.getValue().expiredAt(now));

        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        int ttl = step == LoginStep.BIND_TOTP ? BIND_TTL_SECONDS : TTL_SECONDS;
        tickets.put(value, new PreAuthTicket(value, userId, step, identityType, now + ttl * 1000L));
        session.setAttribute(SESSION_KEY, tickets);
        return value;
    }

    /**
     * 校验并取出 ticket。
     *
     * @param allowedSteps 允许的步骤（空表示不限）
     * @throws ApiException {@link ApiErrorCode#TICKET_EXPIRED} 票据不存在/过期/步骤不符
     */
    public PreAuthTicket require(HttpSession session, String ticket, LoginStep... allowedSteps) {
        Map<String, PreAuthTicket> tickets = tickets(session);
        PreAuthTicket value = ticket == null ? null : tickets.get(ticket);
        if (value == null) {
            throw new ApiException(ApiErrorCode.TICKET_EXPIRED, "admin-auth.error.ticket-not-found");
        }
        if (value.expiredAt(clock.now().toEpochMilli())) {
            tickets.remove(ticket);
            session.setAttribute(SESSION_KEY, tickets);
            throw new ApiException(ApiErrorCode.TICKET_EXPIRED, "admin-auth.error.ticket-invalid");
        }
        if (allowedSteps != null && allowedSteps.length > 0
                && java.util.Arrays.stream(allowedSteps).noneMatch(step -> step == value.step())) {
            throw new ApiException(ApiErrorCode.TICKET_EXPIRED, "admin-auth.error.ticket-step-mismatch");
        }
        return value;
    }

    /** 成功后消费（单次有效）。 */
    public void consume(HttpSession session, String ticket) {
        Map<String, PreAuthTicket> tickets = tickets(session);
        tickets.remove(ticket);
        session.setAttribute(SESSION_KEY, tickets);
    }

    /**
     * 记录一次校验失败：超过 5 次则作废票据。
     *
     * @return true=票据仍可用；false=已作废（调用方返回 423）
     */
    public boolean registerFailure(HttpSession session, PreAuthTicket ticket) {
        Map<String, PreAuthTicket> tickets = tickets(session);
        int attempts = ticket.incrementAttempts();
        if (attempts >= MAX_ATTEMPTS) {
            tickets.remove(ticket.value());
            session.setAttribute(SESSION_KEY, tickets);
            return false;
        }
        session.setAttribute(SESSION_KEY, tickets);
        return true;
    }

    @SuppressWarnings("unchecked")
    private Map<String, PreAuthTicket> tickets(HttpSession session) {
        Object attribute = session.getAttribute(SESSION_KEY);
        if (attribute instanceof Map<?, ?> map) {
            return (Map<String, PreAuthTicket>) map;
        }
        return new HashMap<>();
    }
}
