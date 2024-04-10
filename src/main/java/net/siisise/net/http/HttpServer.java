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
package net.siisise.net.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.abnf.rfc.HTTP9112;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.io.FileIO;
import net.siisise.io.FrontPacket;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.json.JSONObject;

/**
 * OAuth client 用の簡易HTTPサーバ.
 * セッション1つ、データ1つのみ返す。
 * 何故作るはめに
 * 
 * ToDo HTTP/2, WebSocket へのUpgrage
 */
public class HttpServer implements Runnable {
    private ServerSocket serverSocket;
    private Thread thread;
    Map<String,Function<JSONObject,Object>> pagemap = new HashMap<>();

    /**
     * callback Local用 とりあえず
     */
    public HttpServer() {
        
    }

    /**
     * URLを指定しないで全般に.
     * 
     * @param page
     */
    public void callback(Function<JSONObject,Object> page) {
        pagemap.put(null, page);
    }

    public void callback(String path, Function<JSONObject,Object> page) {
        pagemap.put(path, page);
    }

    /**
     * すたーと
     * @param addr
     * @param port ポート番号 または 0で自動割り当て
     * @return 動いてたらポート
     * @throws java.io.IOException 
     */
    public int start(InetAddress addr, int port) throws IOException {
        serverSocket = new ServerSocket(port,1, addr);
        port = serverSocket.getLocalPort();
        thread = new Thread(this);
        thread.start();
        return port;
    }

    public void close() throws IOException {
        if ( serverSocket != null ) {
            serverSocket.close();
            serverSocket = null;
        }
    }

    static final ABNFReg REG = new ABNFReg(HTTP9112.REG);
    
    // body を外したもの
//    static final ABNF HTTPheader2 = REG.rule("http-header2",HTTP9112.REG.ref("start-line").plu(ABNF5234.CRLF, HTTP9112.fieldLine.pl(ABNF5234.CRLF).x(), ABNF5234.CRLF));
    
    static final ABNF REQUESTLINE = REG.rule("rql", HTTP9112.REG.ref("request-line").pl(ABNF5234.CRLF));
    static final ABNF TS = REG.ref("trailer-section");
    static final ABNF FIELDLINE2 = REG.rule("fl2",REG.ref("trailer-section").pl(ABNF5234.CRLF));
    
    String[] responses = {
        "HTTP/1.1 200 OK",
        "Server: Siisise Callback",
        "Content-Type: application/json; charset=utf-8"
    };

    String[] hds = {"method", "request-target"};
    
    String[] qs = {"query"};

    /**
     * 
     * @param pac
     * @return 
     */
    static FrontPacket dump(FrontPacket pac) {
        System.out.println(pac.size());
        byte[] d = new byte[pac.size()];
        pac.read(d);
        pac.backWrite(d);
        
        dump(d);
        return pac;
    }
    
    static void dump(ReadableBlock rb) {
        System.out.println(rb.length());
        byte[] d = new byte[rb.size()];
        rb.read(d);
        rb.back(d.length);
        dump(d);
    }
    
    static byte[] dump(byte[] src) {
        for ( int i = 0; i < src.length; i++ ) {
            String s = "0" + Integer.toHexString(src[i] & 0xff);
            System.out.print( " " + s.substring(s.length() - 2));
            if ( i % 16 == 15 ) {
                System.out.println();
            }
        }
        System.out.println();
        System.out.println("HttpServer dump : ");
        System.out.println(new String(src, StandardCharsets.UTF_8));
        return src;
    }
    
    static String strd(Packet pac) {
        byte[] d = pac.toByteArray();
        pac.backWrite(d);
        return new String(d, StandardCharsets.UTF_8);
    }

    /**
     * パターン待ち. 仮
     * ABNFルールに一致するまで待つよ
     * @param in 入力
     * @param rulename ABNFルール名
     * @param subrules サブルール
     * @return 抽出結果
     * @throws IOException 
     */
    ABNF.Match<Packet> wait(Packet pac, InputStream in, String rulename, String... subrules) throws IOException {
        ABNF.Match<Packet> request;
        do {
            pac.write(FileIO.readAvailablie(in));
            request = REG.find(pac, rulename, subrules);
        } while ( request == null);
        return request;
    }
    
    /**
     * Java EE っぽい.
     * @param soc
     * @throws IOException 
     */
    void connect(Socket soc) throws IOException {
        System.out.println("connect...");
        System.out.println("port: " + soc.getPort());
        System.out.println("localport: " + soc.getLocalPort());
        try {
            InputStream in = soc.getInputStream();
            OutputStream out = soc.getOutputStream();

            Packet pac = new PacketA();

            // HTTP/1.1 待ち
            ABNF.Match<Packet> request = wait(pac, in, "rql", "method", "request-target");
            dump(request.sub);
            dump(pac);

//            ABNF.Match<Packet> trailer = REG.find(pac, "trailer-section", "field-line");
//                trailer = REG.find(pac, "trailer-section", "field-line");
            ABNF.Match<Packet> trailer = REG.find(pac, "fl2","field-line");
            if ( trailer == null ) {
                trailer = wait(pac, in,"trailer-section","field-line");
            }
            dump(trailer.sub);

//            dump(fl);

            JSONObject params = new JSONObject();

            Packet method = request.get("method").get(0);
            Packet target = request.get("request-target").get(0);
            params.put("method", strd(method));
            params.put("request-target", strd(target));
            BNF.Match<Packet> queryMatch = HTTP9112.REG.find(target, "request-target", "absolute-path","query");
            String absolutePath = strd(queryMatch.get("absolute-path").get(0));
            // ToDo: absolutePath の正規化
            params.put("absolute-path", absolutePath);
            String query = strd(queryMatch.get("query").get(0));
            Map <String,String> queryMap = HttpEncode.decodeQuery(query);
            //JSONValue queryJson = JSON.valueOf(queryMap);
            params.put("query", queryMap);

//            ABNF.Match linematch = REG.find(trailer.sub,"trailer", "field-line");
            List<Packet> lineps = trailer.get("field-line");
            if ( lineps != null) {
                List<String> lines = lineps.stream().map(v -> strd(v)).collect(Collectors.toList());
                params.put("req", lines);
            }
            params.put("linelen", trailer.sub.length());

            Function<JSONObject,Object> page = pagemap.get(absolutePath);
            if ( page == null ) {
                page = pagemap.get(null);
            }
            Object result = page.apply(params);

            StringBuilder rh = new StringBuilder();
            // response header
            for ( String h : responses ) {
                rh.append(h);
                rh.append("\r\n");
            }
            rh.append("\r\n");

            Charset utf8 = StandardCharsets.UTF_8;
            out.write(rh.toString().getBytes(utf8));
            //out.write("\r\n".getBytes(utf8));
            // body
            if ( result instanceof JSONObject ) {
                String json = ((JSONObject)result).toJSON();
                out.write(json.getBytes(utf8));
            } else {
                out.write(((String)result).getBytes(utf8));
            }
            out.write("\r\n".getBytes(utf8));
            out.flush();
        } finally {
            soc.close();
            close();
        }
    }

    /**
     * 何かそんな感じで動くだけ.
     */
    @Override
    public void run() {
        try {
            Socket soc = serverSocket.accept();
            connect(soc); // 1回だけ
        } catch (IOException ex) {
            ex.printStackTrace();
            // 繋がらない
        }
    }
}
