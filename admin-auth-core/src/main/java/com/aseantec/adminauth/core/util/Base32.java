package com.aseantec.adminauth.core.util;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

/** RFC 4648 Base32（无填充）编解码，用于 TOTP 共享密钥。 */
public final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] LOOKUP = new int[128];

    static {
        Arrays.fill(LOOKUP, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            LOOKUP[ALPHABET[i]] = i;
            LOOKUP[Character.toLowerCase(ALPHABET[i])] = i;
        }
    }

    private Base32() {
    }

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                out.append(ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            out.append(ALPHABET[(buffer << (5 - bitsLeft)) & 0x1F]);
        }
        return out.toString();
    }

    public static byte[] decode(String text) {
        if (text == null) {
            throw new IllegalArgumentException("Base32 输入不能为空");
        }
        String value = text.trim().replace("=", "").replace(" ", "").toUpperCase(Locale.ROOT);
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length() * 5 / 8 + 1);
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            int v = c < 128 ? LOOKUP[c] : -1;
            if (v < 0) {
                throw new IllegalArgumentException("非法 Base32 字符: " + c);
            }
            buffer = (buffer << 5) | v;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
