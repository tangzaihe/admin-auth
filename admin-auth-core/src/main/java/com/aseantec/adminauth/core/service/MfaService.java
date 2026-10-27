package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.crypto.RecoveryCodeHasher;
import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.domain.FactorStatus;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import com.aseantec.adminauth.core.domain.MfaVerificationException;
import com.aseantec.adminauth.core.domain.RecoveryCode;
import com.aseantec.adminauth.core.domain.TotpSetupResult;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.MfaFactorRepository;
import com.aseantec.adminauth.core.port.RecoveryCodeRepository;
import com.aseantec.adminauth.core.port.SecretCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 第二因素领域服务：TOTP 绑定 / 校验 / 恢复码 / 停用。
 *
 * <p><b>链路（绑定）</b></p>
 * <ol>
 *   <li>{@link #beginTotpSetup}：生成 20B 随机 secret → AES-GCM 加密落
 *       {@code adm_mfa_factor(status=PENDING)}；明文 secret 只出现在本次响应，绝不落库；</li>
 *   <li>{@link #confirmTotpSetup}：解密 PENDING secret → 校验 6 位码（±window）
 *       → 置 {@code ACTIVE} 并推进 {@code last_used_step}（首个码不可重放）
 *       → 生成 10 个恢复码（明文只返回一次，库存 HMAC-SHA256）。</li>
 * </ol>
 *
 * <p><b>链路（登录校验）</b>：取账号 ACTIVE 因素 → 解密 secret → 在 ±window 内匹配
 * → 命中时间步必须大于 {@code last_used_step} 才能原子推进（防重放）→ 失败累计到阈值则因素级锁定。</p>
 *
 * <p><b>链路（恢复码）</b>：对提交值重算 HMAC → 与库存逐条恒定时间比较 → {@code markUsed}
 * 原子核销（{@code WHERE used_at IS NULL}）→ 删除全部因素与剩余恢复码（用后强制重绑）。</p>
 */
public class MfaService {

    private static final Logger log = LoggerFactory.getLogger(MfaService.class);

    /** 恢复码字符集：去掉易混淆的 I/O/0/1。 */
    private static final char[] RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final int RECOVERY_CODE_COUNT = 10;
    private static final int RECOVERY_CODE_LENGTH = 10;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AdminUserRepository users;
    private final MfaFactorRepository factors;
    private final RecoveryCodeRepository recoveryCodes;
    private final SecretCipher cipher;
    private final TotpService totp;
    private final RecoveryCodeHasher recoveryCodeHasher;
    private final ClockProvider clock;
    private final AuditSink audit;
    private final Settings settings;
    private final int maxAttempts;
    private final Duration lockDuration;

    public MfaService(AdminUserRepository users,
                      MfaFactorRepository factors,
                      RecoveryCodeRepository recoveryCodes,
                      SecretCipher cipher,
                      TotpService totp,
                      RecoveryCodeHasher recoveryCodeHasher,
                      ClockProvider clock,
                      AuditSink audit,
                      Settings settings,
                      int maxAttempts,
                      Duration lockDuration) {
        this.users = users;
        this.factors = factors;
        this.recoveryCodes = recoveryCodes;
        this.cipher = cipher;
        this.totp = totp;
        this.recoveryCodeHasher = recoveryCodeHasher;
        this.clock = clock;
        this.audit = audit;
        this.settings = settings;
        this.maxAttempts = Math.max(1, maxAttempts);
        this.lockDuration = lockDuration == null ? Duration.ofMinutes(15) : lockDuration;
    }

    /** TOTP 参数：issuer 用于 otpauth URI，digits/period 与因素表字段保持一致。 */
    public record Settings(String issuer, int digits, int period, int window) {
        public Settings {
            issuer = issuer == null || issuer.isBlank() ? "Admin Auth" : issuer;
            digits = digits < 6 || digits > 8 ? 6 : digits;
            period = period <= 0 ? 30 : period;
            window = Math.max(0, window);
        }
    }

    /**
     * 开始绑定 TOTP：生成新 secret 并写入 PENDING 因素。
     * <p>已存在 ACTIVE TOTP 时拒绝；已存在 PENDING 时复用行、重新生成 secret（旧扫码作废）。</p>
     */
    public TotpSetupResult beginTotpSetup(long userId, String accountName) {
        requireUser(userId);
        if (factors.findActiveByUserIdAndType(userId, MfaFactorType.TOTP).isPresent()) {
            throw new IllegalStateException("TOTP 已绑定，请先停用后再重新绑定");
        }
        byte[] secret = totp.randomSecret();
        String base32 = totp.encodeBase32(secret);
        byte[] secretEnc = cipher.encrypt(secret);

        MfaFactor pending = factors.findPendingByUserIdAndType(userId, MfaFactorType.TOTP).orElse(null);
        if (pending == null) {
            factors.insert(new MfaFactor(0L, userId, MfaFactorType.TOTP, 0L, secretEnc, cipher.keyVersion(),
                    settings.digits(), settings.period(), 0L, null, 10, null, 0, null, FactorStatus.PENDING));
        } else {
            factors.updateSecret(pending.id(), secretEnc, cipher.keyVersion());
            factors.updateStatus(pending.id(), FactorStatus.PENDING);
        }
        String account = accountName == null || accountName.isBlank() ? String.valueOf(userId) : accountName;
        String uri = totp.otpauthUri(settings.issuer(), account, base32, settings.digits(), settings.period());
        log.debug("TOTP 绑定已初始化 userId={}", userId);
        return new TotpSetupResult(base32, uri);
    }

    /** 确认绑定：校验首个动态码，激活因素并一次性返回恢复码明文。 */
    public List<String> confirmTotpSetup(long userId, String code) {
        MfaFactor pending = factors.findPendingByUserIdAndType(userId, MfaFactorType.TOTP)
                .orElseThrow(() -> new MfaVerificationException("TOTP 绑定已失效，请重新开始"));
        Instant now = clock.now();
        byte[] secret = cipher.decrypt(pending.keyVersion(), pending.secretEnc());
        long step = totp.matchStep(secret, code, now.getEpochSecond(),
                pending.digits(), pending.period(), settings.window());
        if (step < 0) {
            throw new MfaVerificationException("验证码不正确");
        }
        factors.activate(pending.id(), now);
        factors.advanceLastUsedStep(pending.id(), step, now);
        List<String> codes = generateRecoveryCodes();
        recoveryCodes.replaceForUser(userId, codes.stream().map(recoveryCodeHasher::hash).toList(), now);
        users.updateMfaState(userId, 1);
        recordAudit(userId, MfaFactorType.TOTP, AuditEvent.MFA_BIND, AuditResult.SUCCESS, now, null);
        return codes;
    }

    /**
     * 校验 TOTP 动态码（防重放 + 因素级锁定）。
     *
     * @return true=校验通过
     * @throws MfaVerificationException 码错误 / 重放 / 因素锁定
     */
    public boolean verifyTotp(long userId, String code) {
        Instant now = clock.now();
        List<MfaFactor> totpFactors = factors.findActiveByUserId(userId).stream()
                .filter(f -> f.factorType() == MfaFactorType.TOTP)
                .toList();
        if (totpFactors.isEmpty()) {
            throw new MfaVerificationException("尚未绑定 TOTP");
        }
        for (MfaFactor factor : totpFactors) {
            if (factor.lockedAt(now)) {
                recordAudit(userId, MfaFactorType.TOTP, AuditEvent.MFA_VERIFY_FAIL, AuditResult.FAIL, now,
                        "{\"reason\":\"FACTOR_LOCKED\"}");
                throw new MfaVerificationException("第二因素尝试次数过多，请稍后再试", true);
            }
            byte[] secret = cipher.decrypt(factor.keyVersion(), factor.secretEnc());
            long step = totp.matchStep(secret, code, now.getEpochSecond(),
                    factor.digits(), factor.period(), settings.window());
            if (step < 0) {
                continue;
            }
            // 原子推进 last_used_step：只有严格大于旧值才成功，同一时间步不可二次使用
            if (factors.advanceLastUsedStep(factor.id(), step, now)) {
                factors.resetFailure(factor.id(), now);
                recordAudit(userId, MfaFactorType.TOTP, AuditEvent.MFA_VERIFY_OK, AuditResult.SUCCESS, now, null);
                return true;
            }
            recordFactorFailure(factor, now, "REPLAY");
        }
        recordFactorFailure(totpFactors.get(0), now, "CODE_MISMATCH");
        return false;
    }

    /** 恢复码登录：核销成功即删除全部因素与恢复码（用后强制重绑）。 */
    public boolean verifyRecoveryCode(long userId, String code) {
        Instant now = clock.now();
        String submittedHash = recoveryCodeHasher.hash(code);
        for (RecoveryCode recoveryCode : recoveryCodes.findUnusedByUserId(userId)) {
            boolean match = MessageDigest.isEqual(
                    recoveryCode.codeHash().getBytes(StandardCharsets.US_ASCII),
                    submittedHash.getBytes(StandardCharsets.US_ASCII));
            if (match && recoveryCodes.markUsed(recoveryCode.id(), now)) {
                factors.deleteByUserId(userId);
                recoveryCodes.deleteByUserId(userId);
                users.updateMfaState(userId, 0);
                recordAudit(userId, null, AuditEvent.MFA_VERIFY_OK, AuditResult.SUCCESS, now,
                        "{\"factor\":\"RECOVERY\"}");
                log.info("恢复码登录成功，已强制重绑 userId={}", userId);
                return true;
            }
        }
        recordAudit(userId, null, AuditEvent.MFA_VERIFY_FAIL, AuditResult.FAIL, now,
                "{\"factor\":\"RECOVERY\"}");
        return false;
    }

    /** 用户自助停用 TOTP。 */
    public void disable(long userId) {
        reset(userId, AuditEvent.MFA_DISABLE);
    }

    /** 管理员重置 2FA（删除因素 + 恢复码，mfa_state=0）。 */
    public void adminReset(long userId) {
        reset(userId, AuditEvent.MFA_RESET);
    }

    public List<MfaFactor> listFactors(long userId) {
        return factors.findByUserId(userId);
    }

    private void reset(long userId, AuditEvent event) {
        Instant now = clock.now();
        factors.deleteByUserId(userId);
        recoveryCodes.deleteByUserId(userId);
        users.updateMfaState(userId, 0);
        recordAudit(userId, null, event, AuditResult.SUCCESS, now, null);
        log.info("MFA 已重置 userId={} event={}", userId, event);
    }

    /** 因素级失败计数：达到阈值时写入 locked_until 并抛出带 locked 标记的异常。 */
    private void recordFactorFailure(MfaFactor factor, Instant now, String reason) {
        int count = factor.failCount() + 1;
        Instant lockedUntil = count >= maxAttempts ? now.plus(lockDuration) : null;
        factors.recordFailure(factor.id(), count, lockedUntil, now);
        recordAudit(factor.userId(), MfaFactorType.TOTP, AuditEvent.MFA_VERIFY_FAIL, AuditResult.FAIL, now,
                "{\"reason\":\"" + reason + "\"}");
        if (lockedUntil != null) {
            throw new MfaVerificationException("第二因素尝试次数过多，请稍后再试", true);
        }
    }

    private List<String> generateRecoveryCodes() {
        List<String> codes = new ArrayList<>(RECOVERY_CODE_COUNT);
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            StringBuilder sb = new StringBuilder(RECOVERY_CODE_LENGTH + 1);
            for (int j = 0; j < RECOVERY_CODE_LENGTH; j++) {
                if (j == RECOVERY_CODE_LENGTH / 2) {
                    sb.append('-');
                }
                sb.append(RECOVERY_ALPHABET[RANDOM.nextInt(RECOVERY_ALPHABET.length)]);
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    private AdminUser requireUser(long userId) {
        return users.findById(userId)
                .orElseThrow(() -> new IllegalStateException("账号不存在: " + userId));
    }

    private void recordAudit(long userId, MfaFactorType factorType, AuditEvent event, AuditResult result,
                             Instant now, String detail) {
        try {
            audit.record(new AuditEntry(userId, null, "", factorType == null ? "" : factorType.name(), "",
                    event, result, "", "", detail, now));
        } catch (RuntimeException e) {
            log.warn("审计写入失败（已忽略，不影响主流程）: {}", e.getMessage());
        }
    }
}
