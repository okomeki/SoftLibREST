/*
 * Copyright 2022 okome.
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
import java.util.LinkedHashMap;
import java.util.Map;
import net.siisise.io.BASE64;

/**
 *
 * ToDo: RFC 2617 -> RFC 7617 BASIC認証
 */
public class HttpClient extends HttpEncode {

    protected String baseuri;
    protected Map<String, String> headers = new LinkedHashMap<>();

    public void setBaseURI(String base) {
        baseuri = base;
    }
    
    public void addHeader(String name, String body) {
        headers.put(name, body);
    }

    /**
     * RFC 7617 BASIC認証.
     * ユーザに':'が含まれていた場合の結果は保証しない。
     * TLS上で使用すること。
     * NFC 正規化
     * ID RFC 7613 Section 3.3.
     * password RFC 7613 Section 4.2.
     * 
     * RFC 7235 Authorization
     *
     * @param user ':' を含まないUnicode文字列
     * @param pass なんでもUnicode文字列
     */
    public void setBasicAuthorization(String user, String pass) {
        String code = user + ":" + pass;
        BASE64 b64 = new BASE64(BASE64.BASE64, 0);
        headers.put("Authorization", "Basic " + b64.encode(code.getBytes(StandardCharsets.UTF_8)));
    }
}
