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

import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.bnf.BNFReg;
import net.siisise.bnf.parser.BNFBaseParser;

/**
 *
 */
public class PCTdce extends BNFBaseParser<Byte> {
    
    public PCTdce(BNF bnf, BNFReg reg) {
        super(bnf);
        
    }

    @Override
    public Byte parse(ReadableBlock pac) {
        pac.read(); // %
        byte[] st = new byte[2];
        pac.read(st);
        return Byte.valueOf(new String(st), 16);
    }
    
}
