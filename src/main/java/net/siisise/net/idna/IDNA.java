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
package net.siisise.net.idna;

import java.text.Normalizer;

/**
 * IDNA あとで分けるかも.
 * RFC 3490 IDNA
 * RFC 3491 Nameprep
 * RFC 3492 Punycode
 */
public class IDNA {
    
    public static String idnaEncode(String src) {
        return java.net.IDN.toASCII(src);
        //return punycodeEncode(nameprepEncode(src));
    }
    
/*    
    static String nameprepEncode(String src) {
        Normalizer.normalize(src, Normalizer.Form.NFKC);
        return src;
    }
    
    static String punycodeEncode(String src) {
        return src;
    }
*/
}
