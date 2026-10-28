package com.aseantec.adminauth.starter.admin;

import com.aseantec.adminauth.core.service.MfaService;
import com.aseantec.adminauth.core.service.PasswordService;
import com.aseantec.adminauth.starter.web.ApiErrorCode;
import com.aseantec.adminauth.starter.web.ApiException;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

/**
 * 多写操作的统一事务边界（core 层保持纯 Java，不引入 Spring 事务注解）。
 *
 * <p>覆盖：TOTP 确认（激活因素 + 恢复码 + mfa_state + 审计）、恢复码登录（删因素 + 删码 + 状态）、
 * 停用/重置 2FA、改密（密码 + token_version + 审计）。</p>
 */
public class AdminAuthTransactionalOperations {

    private final TransactionTemplate transactionTemplate;
    private final MfaService mfaService;
    private final PasswordService passwordService;

    public AdminAuthTransactionalOperations(TransactionTemplate transactionTemplate,
                                            MfaService mfaService,
                                            PasswordService passwordService) {
        this.transactionTemplate = transactionTemplate;
        this.mfaService = mfaService;
        this.passwordService = passwordService;
    }

    public List<String> confirmTotpSetup(long userId, String code) {
        List<String> codes = transactionTemplate.execute(status -> mfaService.confirmTotpSetup(userId, code));
        if (codes == null) {
            throw new ApiException(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.totp-bind-failed");
        }
        return codes;
    }

    public boolean verifyTotp(long userId, String code) {
        return Boolean.TRUE.equals(transactionTemplate.execute(status -> mfaService.verifyTotp(userId, code)));
    }

    public boolean verifyRecoveryCode(long userId, String code) {
        return Boolean.TRUE.equals(transactionTemplate.execute(status -> mfaService.verifyRecoveryCode(userId, code)));
    }

    public void changePassword(long userId, String oldPassword, String newPassword, boolean initialChange) {
        transactionTemplate.executeWithoutResult(status ->
                passwordService.changePassword(userId, oldPassword, newPassword, initialChange));
    }

    public void disableMfa(long userId) {
        transactionTemplate.executeWithoutResult(status -> mfaService.disable(userId));
    }

    public void adminResetMfa(long userId) {
        transactionTemplate.executeWithoutResult(status -> mfaService.adminReset(userId));
    }
}
