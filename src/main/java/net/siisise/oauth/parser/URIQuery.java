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

import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.bnf.BNF;
import net.siisise.bnf.BNFReg;
import net.siisise.bnf.parser.BNFList;

/**
 *
 */
public class URIQuery extends BNFList<List,Object> {
    static final ABNFReg REG = new ABNFReg();
    
    static ABNF pctEnc = REG.rule("pctEnc", PCTdce.class, ABNF.bin('%').pl(ABNF5234.DIGIT.x(2)));
    static ABNF name = REG.rule("name", "");
    static ABNF value = REG.rule("value", "");
    static ABNF set = REG.rule("set",name.pl(ABNF.bin('='),value));
    static ABNF query = REG.rule("query", URIQuery.class, set);
    
    public URIQuery(BNF bnf, BNFReg reg) {
        super(bnf,reg);
    }

    @Override
    protected List build(List<Object> list) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
