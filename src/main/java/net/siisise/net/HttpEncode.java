/*
 * Copyright 2023 Siisise Net.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.net;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * とりあえずHTTP 系.
 * HTML系, URL系はわける.
 */
public class HttpEncode {

    /**
     * percent-encoding.
     * application/x-www-form-urlencoded 専用
     * RFC 3986 Section 2.1. ではない ? '*' と '~' がちがう
     * RFC 7xxx
     * をUTF-8に対応してみたら
     *
     * https://developer.mozilla.org/ja/docs/Glossary/percent-encoding の標準ではない形
     * 
     * RFC 1866 Section 8.2.1. The form-urlencoded Media Type
     * url-standard 5
     * 
     * @param src Unicode 文字列
     * @return URI用ASCIIっぽい文字列
     */
    public static String formPercentEncode(String src) {
        int[] cps = src.codePoints().toArray();
        StringBuilder sb = new StringBuilder();
        for (int cp : cps) {
            if ((cp >= '0' && cp <= '9')
                    || (cp >= 'a' && cp <= 'z')
                    || (cp >= 'A' && cp <= 'Z')
                    || cp == '*' || cp == '-' || cp == '.' || cp == '_') {
                sb.appendCodePoint(cp);
            } else if (cp == ' ') {
                sb.append('+');
            } else {
                byte[] bs = String.valueOf(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
                for (byte b : bs) {
                    String bc = "0" + Integer.toHexString(b & 0xff);
                    sb.append('%');
                    sb.append(bc.substring(bc.length() - 2));
                }
            }
        }
        return sb.toString();
    }

    private static boolean isHex(byte c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * パーセントエンコードのデコード.
     * @param encd エスケープ済みURI系文字列
     * @return Unicode文字列
     */
    public static String formPercentDecode(String encd) {
        Packet src = new PacketA(encd.getBytes(StandardCharsets.UTF_8));
        Packet dec = new PacketA();
        while (src.size() > 0) {
            byte c = (byte) src.read();
            if (c == '%' && src.length() >= 2) {
                byte[] o = new byte[2];
                src.read(o);
                if (isHex(o[0]) && isHex(o[1])) {
                    c = Byte.parseByte(new String(o, StandardCharsets.UTF_8), 16);
                } else {
                    src.backWrite(o);
                }
            } else if (c == '+') {
                c = ' ';
            }
            dec.write(new byte[]{c});
        }
        return new String(dec.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * queryのデコード、仮置き場
     * @param query 
     * @return map か jsonにする予定
     */
    public static Map<String,String> decodeQuery(String query) {
        Map<String,String> paramsmap = new HashMap<>();
        if ( query != null ) {
            String[] params = query.split("&");
            for ( String param : params ) {
                String[] kv = param.split("=");
                if ( kv.length >= 2) {
                    paramsmap.put(formPercentDecode(kv[0]), formPercentDecode(kv[1]));
                }
            }
        }
        return paramsmap;
    }
}
