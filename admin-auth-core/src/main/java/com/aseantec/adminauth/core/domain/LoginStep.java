package com.aseantec.adminauth.core.domain;

/** 登录后续步骤（登录首步与 ticket 流转的步骤集合）。 */
public enum LoginStep {
    /** 认证完成，可建立会话。 */
    COMPLETE,
    /** 需要选择并校验第二因素。 */
    SELECT_FACTOR,
    /** 需要先绑定 TOTP。 */
    BIND_TOTP,
    /** 需要先修改初始密码。 */
    CHANGE_PASSWORD
}
