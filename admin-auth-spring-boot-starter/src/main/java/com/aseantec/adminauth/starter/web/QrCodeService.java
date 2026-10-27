package com.aseantec.adminauth.starter.web;

import io.nayuki.qrcodegen.QrCode;

/** 服务端二维码：qrcodegen 生成模块矩阵后手工拼 SVG（无外网、无前端二维码库）。 */
public class QrCodeService {

    private static final int BORDER = 2;

    public String toSvg(String text) {
        QrCode qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
        int size = qr.size;
        int total = size + BORDER * 2;
        StringBuilder path = new StringBuilder(size * size * 4);
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                if (qr.getModule(x, y)) {
                    path.append('M').append(x + BORDER).append(' ').append(y + BORDER).append("h1v1h-1z");
                }
            }
        }
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"240\" height=\"240\" viewBox=\"0 0 "
                + total + " " + total + "\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"TOTP QR\">"
                + "<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>"
                + "<path d=\"" + path + "\" fill=\"#111111\"/></svg>";
    }
}
