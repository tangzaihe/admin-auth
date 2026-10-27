package com.aseantec.adminauth.starter.keys;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 密钥解析：{@code env:NAME} 取环境变量，{@code base64:...} 解码，其余按 UTF-8 明文解释。
 * <p>长度必须为 32 字节，否则启动失败；只记录来源，绝不打印密钥本身。</p>
 *
 * <p>支持数据密钥轮换：{@code data-kek-version} 指定当前版本，{@code data-kek-history}
 * 保存旧版本密钥（{@code version -> key}），用于解密历史密文。</p>
 */
public record KeyMaterial(
        int dataKekVersion,
        byte[] dataKek,
        Map<Integer, byte[]> dataKekHistory,
        byte[] indexKey,
        byte[] otpKey,
        String dataKekSource,
        String dataKekHistorySource,
        String indexKeySource,
        String otpKeySource) {

    public KeyMaterial {
        dataKekHistory = dataKekHistory == null ? Map.of() : Map.copyOf(dataKekHistory);
    }

    /** 当前密钥 + 历史密钥，供 {@code AesGcmSecretCipher} 构造 keyring。 */
    public Map<Integer, byte[]> allDataKeks() {
        Map<Integer, byte[]> all = new LinkedHashMap<>(dataKekHistory);
        all.put(dataKekVersion, dataKek);
        return all;
    }

    public static KeyMaterial resolve(int currentVersion, String dataKek, Map<Integer, String> history,
                                      String indexKey, String otpKey) {
        Resolved data = resolveOne("data-kek", dataKek);
        Resolved index = resolveOne("index-key", indexKey);
        Resolved otp = resolveOne("otp-key", otpKey);

        Map<Integer, byte[]> historyKeys = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> entry : (history == null ? Map.<Integer, String>of() : history).entrySet()) {
            historyKeys.put(entry.getKey(), resolveOne("data-kek-history[" + entry.getKey() + "]", entry.getValue()).bytes());
        }
        String historySource = historyKeys.isEmpty()
                ? "none"
                : "versions=" + historyKeys.keySet();
        return new KeyMaterial(currentVersion, data.bytes(), historyKeys, index.bytes(), otp.bytes(),
                data.source(), historySource, index.source(), otp.source());
    }

    private static Resolved resolveOne(String name, String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException("admin-auth.keys." + name + " 未配置：请提供 32 字节密钥（支持 env:/base64:）");
        }
        String value = raw.trim();
        byte[] bytes;
        String source;
        if (value.startsWith("env:")) {
            String envName = value.substring("env:".length()).trim();
            String envValue = System.getenv(envName);
            if (envValue == null || envValue.isBlank()) {
                throw new IllegalStateException("admin-auth.keys." + name + " 引用的环境变量不存在: " + envName);
            }
            bytes = envValue.getBytes(StandardCharsets.UTF_8);
            source = "env:" + envName;
        } else if (value.startsWith("base64:")) {
            try {
                bytes = Base64.getDecoder().decode(value.substring("base64:".length()).trim());
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("admin-auth.keys." + name + " 不是合法的 Base64");
            }
            source = "base64";
        } else {
            bytes = value.getBytes(StandardCharsets.UTF_8);
            source = "raw";
        }
        if (bytes.length != 32) {
            throw new IllegalStateException("admin-auth.keys." + name + " 必须为 32 字节（当前 " + bytes.length
                    + " 字节，来源 " + source + "）");
        }
        return new Resolved(bytes, source);
    }

    private record Resolved(byte[] bytes, String source) {
    }
}
