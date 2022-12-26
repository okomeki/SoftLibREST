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
package net.siisise.oauth.parser;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.abnf.rfc.URI3986;

/**
 * RFC 6750.
 * Appendix A. Augmented Backus-Naur Form (ABNF) Syntax
 */
public class OAuth6750 {

    public static final ABNFReg REG = new ABNFReg();

    public static final ABNF VSCHAR = REG.rule("VSCHAR", ABNF.range(0x20, 0x7e));
    public static final ABNF NQCHAR = REG.rule("NQCHAR", ABNF.bin(0x21).or1(ABNF.range(0x23, 0x5b), ABNF.range(0x5d, 0x7e)));
    public static final ABNF NQSCHAR = REG.rule("NQSCHAR", ABNF.range(0x20, 0x21).or1(ABNF.range(0x23, 0x5b), ABNF.range(0x5d, 0x7e)));
    public static final ABNF UNICODECHARNOCRLF = REG.rule("UNICODECHARNOCRLF", ABNF.bin(0x09).or1(ABNF.range(0x20, 0x7e), ABNF.range(0x80, 0xd7ff),
            ABNF.range(0xe000, 0xfffd), ABNF.range(0x10000, 0x10ffff)));

    public static final ABNF client_id = REG.rule("clent-id", VSCHAR.x());
    public static final ABNF client_secret = REG.rule("client-secret", VSCHAR.x());
    public static final ABNF response_char = REG.rule("response-char", ABNF.bin('_').or1(ABNF5234.DIGIT, ABNF5234.ALPHA));
    public static final ABNF response_name = REG.rule("response-name", response_char.ix());
    public static final ABNF response_type = REG.rule("response-type", response_name.pl(ABNF5234.SP.pl(response_name).x()));

    public static final ABNF scope_token = REG.rule("scope-token", NQCHAR.ix());
    public static final ABNF scope = REG.rule("scope", scope_token.pl(ABNF5234.SP.pl(scope_token).x()));
    public static final ABNF state = REG.rule("state", VSCHAR.ix());

    public static final ABNF redirect_uri = REG.rule("redirect-uri", URI3986.URIreference);
    public static final ABNF error = REG.rule("error", NQSCHAR.ix());
    public static final ABNF error_description = REG.rule("error-description", NQSCHAR.ix());
    public static final ABNF error_uri = REG.rule("error-uri", URI3986.URIreference);
    public static final ABNF name_char = REG.rule("name-char", ABNF.binlist("-._").or1(ABNF5234.DIGIT, ABNF5234.ALPHA));
    public static final ABNF grant_name = REG.rule("grant-name", name_char.ix());
    public static final ABNF grant_type = REG.rule("grant-type", grant_name.or1(URI3986.URIreference));
    public static final ABNF code = REG.rule("code", VSCHAR.ix());
    public static final ABNF access_token = REG.rule("access-token", VSCHAR.ix());
    public static final ABNF type_name = REG.rule("type-name", name_char.ix());
    public static final ABNF token_type = REG.rule("token-type", type_name.or1(URI3986.URIreference));
    public static final ABNF expores_in = REG.rule("expires-in", ABNF5234.DIGIT.ix());
    public static final ABNF username = REG.rule("username", UNICODECHARNOCRLF.x());
    public static final ABNF password = REG.rule("password", UNICODECHARNOCRLF.x());
    public static final ABNF refresh_token = REG.rule("refresh-token", VSCHAR.ix());
    public static final ABNF param_name = REG.rule("param-name", name_char.ix());

}
