package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.core.port.BlindIndexer;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.IdentityNormalizer;
import com.aseantec.adminauth.core.port.MfaPolicy;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import com.aseantec.adminauth.core.port.SecretCipher;
import com.aseantec.adminauth.core.crypto.AesGcmSecretCipher;
import com.aseantec.adminauth.core.crypto.HmacBlindIndexer;
import com.aseantec.adminauth.core.crypto.RecoveryCodeHasher;
import com.aseantec.adminauth.core.service.DefaultIdentityNormalizer;
import com.aseantec.adminauth.core.service.MfaPolicyService;
import com.aseantec.adminauth.core.service.StaffCodeGenerator;
import com.aseantec.adminauth.core.service.TotpService;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.keys.KeyMaterial;
import com.aseantec.adminauth.starter.spi.BcryptPasswordVerifier;
import com.aseantec.adminauth.starter.web.PreAuthTicketService;
import com.aseantec.adminauth.starter.web.QrCodeService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Instant;

/**
 * 领域层默认 Bean（全部可被宿主同名 Bean 覆盖）。
 * <p>密钥在启动时解析并校验 32 字节，不合法直接失败（fail-fast）。</p>
 */
@Configuration(proxyBeanMethods = false)
public class AdminAuthCoreConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ClockProvider adminAuthClockProvider() {
        return Instant::now;
    }

    @Bean
    @ConditionalOnMissingBean
    public IdentityNormalizer adminAuthIdentityNormalizer() {
        return new DefaultIdentityNormalizer();
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyMaterial adminAuthKeyMaterial(AdminAuthProperties properties) {
        var keys = properties.getKeys();
        return KeyMaterial.resolve(keys.getDataKekVersion(), keys.getDataKek(), keys.getDataKekHistory(),
                keys.getIndexKey(), keys.getOtpKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecretCipher adminAuthSecretCipher(KeyMaterial keyMaterial) {
        return new AesGcmSecretCipher(keyMaterial.dataKekVersion(), keyMaterial.allDataKeks());
    }

    @Bean
    @ConditionalOnMissingBean
    public BlindIndexer adminAuthBlindIndexer(KeyMaterial keyMaterial) {
        return new HmacBlindIndexer(keyMaterial.indexKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public RecoveryCodeHasher adminAuthRecoveryCodeHasher(KeyMaterial keyMaterial) {
        return new RecoveryCodeHasher(keyMaterial.otpKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public TotpService adminAuthTotpService() {
        return new TotpService();
    }

    @Bean
    @ConditionalOnMissingBean
    public StaffCodeGenerator adminAuthStaffCodeGenerator(AdminAuthProperties properties) {
        var staffCode = properties.getIdentity().getStaffCode();
        return new StaffCodeGenerator(staffCode.getPrefix(), staffCode.getDigits(),
                staffCode.getStartOffset(), staffCode.getStrategy());
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordVerifier adminAuthPasswordVerifier(AdminAuthProperties properties) {
        return new BcryptPasswordVerifier(properties.getPassword().getBcryptCost());
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaPolicy adminAuthMfaPolicy(AdminAuthProperties properties) {
        var mfa = properties.getMfa();
        return new MfaPolicyService(mfa.getMode(), mfa.getRequiredRoles(),
                mfa.getRequireTotpRoles(), mfa.isForbidSameChannel());
    }

    @Bean
    @ConditionalOnMissingBean
    public QrCodeService adminAuthQrCodeService() {
        return new QrCodeService();
    }

    @Bean
    @ConditionalOnMissingBean
    public PreAuthTicketService adminAuthPreAuthTicketService(ClockProvider clock) {
        return new PreAuthTicketService(clock);
    }
}
