package com.aseantec.adminauth.starter.web;

/**
 * 业务异常：由 {@link ApiErrorHandler} 统一转换为 {@code {"code","message","messageKey"}}。
 *
 * <p><b>i18n</b>：异常里只放<b>消息键</b>与参数，不放最终文案。
 * {@link #getMessage()} 返回键本身，日志里因此永远是稳定标识，不会随请求语言漂移。</p>
 */
public class ApiException extends RuntimeException {

    private final ApiErrorCode code;
    private final String messageKey;
    private final Object[] args;

    public ApiException(ApiErrorCode code) {
        this(code, code.messageKey());
    }

    /**
     * @param code       稳定错误码（响应里的 {@code code}）
     * @param messageKey 消息键；宿主若直接传文案，未命中键时原样回显（向后兼容）
     * @param args       文案中的 {@code {0}} / {@code {1}} 参数
     */
    public ApiException(ApiErrorCode code, String messageKey, Object... args) {
        super(messageKey);
        this.code = code;
        this.messageKey = messageKey;
        this.args = args == null ? new Object[0] : args;
    }

    public ApiErrorCode code() {
        return code;
    }

    public String messageKey() {
        return messageKey;
    }

    public Object[] args() {
        return args;
    }
}
