package com.aseantec.adminauth.starter.spi;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.port.AdminIdentityRepository;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.BlindIndexer;
import com.aseantec.adminauth.core.port.IdentityNormalizer;
import com.aseantec.adminauth.core.port.MfaFactorRepository;

import java.util.List;
import java.util.Optional;

/** 默认 {@link AdminUserProvider}：规范化 + 盲索引后查 {@code adm_identity}。 */
public class RepositoryAdminUserProvider implements AdminUserProvider {

    private final AdminUserRepository users;
    private final AdminIdentityRepository identities;
    private final MfaFactorRepository factors;
    private final IdentityNormalizer normalizer;
    private final BlindIndexer blindIndexer;

    public RepositoryAdminUserProvider(AdminUserRepository users,
                                       AdminIdentityRepository identities,
                                       MfaFactorRepository factors,
                                       IdentityNormalizer normalizer,
                                       BlindIndexer blindIndexer) {
        this.users = users;
        this.identities = identities;
        this.factors = factors;
        this.normalizer = normalizer;
        this.blindIndexer = blindIndexer;
    }

    @Override
    public Optional<AdminUser> findById(long id) {
        return users.findById(id);
    }

    @Override
    public Optional<AdminUser> findByIdentity(IdentityType type, String rawIdentifier) {
        try {
            String normalized = normalizer.normalize(type, rawIdentifier);
            byte[] index = blindIndexer.index(type, normalized);
            return identities.findActiveByTypeAndHash(type, index)
                    .flatMap(identity -> users.findById(identity.userId()));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    @Override
    public List<AdminIdentity> identitiesOf(long userId) {
        return identities.findByUserId(userId);
    }

    @Override
    public List<MfaFactor> activeFactorsOf(long userId) {
        return factors.findActiveByUserId(userId);
    }
}
