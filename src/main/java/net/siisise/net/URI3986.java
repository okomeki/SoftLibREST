/*
 * Copyright 2023 okome.
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
import net.siisise.block.ReadableBlock;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * RFC ABNF系とあとで混ぜる?
 * @author okome
 */
public class URI3986 {
    

    /**
     * RFC 3986 Section 2.x のpercentEncode.
     * 
     * https://developer.mozilla.org/ja/docs/Glossary/percent-encoding
     * queryでは使わないっぽい
     * 
     * @param src ふつうの文字列
     * @return URLに適した文字列
     */
    public static String urlPercentEncode(String src) {
        byte[] ar = src.getBytes(StandardCharsets.UTF_8);
        ReadableBlock srcBlock = ReadableBlock.wrap(ar);
        Packet rb = new PacketA();
        
        while ( srcBlock.length() > 0 ) {
            ReadableBlock ur = net.siisise.abnf.rfc.URI3986.unreserved.is(srcBlock); // utf-8 バイト単位で読めるかな?
            if (ur != null) {
                rb.write(ur);
            } else {
                rb.write('%');
                int c = (byte)srcBlock.read();
                String b = "0" + Integer.toHexString(c).toUpperCase();
                rb.write(b.substring(b.length()-2).getBytes(StandardCharsets.UTF_8));
            }
        }
        return new String(rb.toByteArray(), StandardCharsets.UTF_8);
    }
    
    public static String urlPercentDecode(String encd) {
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
            }
            dec.write(new byte[]{c});
        }
        return new String(dec.toByteArray(), StandardCharsets.UTF_8);
    }

    private static boolean isHex(byte c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
