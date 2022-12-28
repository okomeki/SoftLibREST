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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.abnf.rfc.HTTP9112;
import net.siisise.bnf.BNF;
import net.siisise.io.FileIO;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.json.JSONObject;
import net.siisise.json.jws.JWS7515;

/**
 * OAuth client 用の簡易HTTPサーバ
 * 何故作るはめに
 */
public class HttpServer implements Runnable {
    ServerSocket serverSocket;
    private Thread thread;
    Map<String,Function<JSONObject,JSONObject>> pagemap = new HashMap<>();

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
    public void callback(Function<JSONObject,JSONObject> page) {
        pagemap.put(null, page);
    }

    /**
     * すたーと
     * @param port ポート番号 または 0
     * @return 動いてたらポート 
     * @throws java.io.IOException 
     */
    public int start(int port) throws IOException {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        serverSocket = new ServerSocket(port,1, loopback);
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

    // body を外したもの
    static final ABNF HTTPheader = HTTP9112.REG.ref("start-line").plu(ABNF5234.CRLF, HTTP9112.fieldLine.pl(ABNF5234.CRLF).x(), ABNF5234.CRLF);
    
    static final ABNFReg REG = new ABNFReg();
    
    static final ABNF REQUESTLINE = HTTP9112.REG.ref("request-line").pl(ABNF5234.CRLF);
    static final ABNF FIELDLINE = HTTP9112.fieldLine.plu(ABNF5234.CRLF).x();
    static final ABNF FIELDLINE2 = HTTP9112.fieldLine.plu(ABNF5234.CRLF).x().pl(ABNF5234.CRLF);
    
    String[] responses = {
        "HTTP/1.1 200 OK",
        "Server: Siisise Callback",
        "Content-Type: text/plain"
    };

    String[] hds = {"method", "request-target"};
    
    String[] qs = {"query"};
    
    Packet dump(Packet pac) {
        byte[] d = new byte[pac.size()];
        pac.read(d);
        pac.write(d);
        for ( int i = 0; i < d.length; i++ ) {
            String s = "0" + Integer.toHexString(d[i] & 0xff);
            System.out.print( " " + s.substring(s.length() - 2));
            if ( i % 16 == 15 ) {
                System.out.println();
            }
        }
        System.out.println();
        System.out.println(new String(d, StandardCharsets.UTF_8));
        return pac;
    }
    
    static String strd(Packet pac) {
        byte[] d = pac.toByteArray();
        pac.backWrite(d);
        return new String(d, StandardCharsets.UTF_8);
    }

    /**
     * 何かそんな感じで動くだけ.
     */
    @Override
    public void run() {
        try {
            Socket soc = serverSocket.accept();
            try {
                InputStream in = soc.getInputStream();
                OutputStream out = soc.getOutputStream();
                Packet pac = new PacketA();
                
                ABNF.Match<Packet> request;
                Packet fl;
                
                do {
                    pac.write(FileIO.readAvailablie(in));
                    request = HTTP9112.REG.find(pac, "request-line", "method", "request-target");
//                    dump(sl);
                } while ( request == null);
                do {
                    pac.write(FileIO.readAvailablie(in));
                    fl = FIELDLINE2.is(pac);
//                    dump(fl);
                } while ( fl == null);
                
                JSONObject params = new JSONObject();
                
                Packet method = request.get("method").get(0);
                Packet target = request.get("request-target").get(0);
                dump(method);
                dump(target);
                params.put("method", strd(method));
                params.put("request-target", strd(target));
                BNF.Match<Packet> queryMatch = HTTP9112.REG.find(target, "request-target", "query");
                params.put("query", strd(queryMatch.get("query").get(0)));
                
                System.out.println(params);
                
                Function<JSONObject,JSONObject> page = pagemap.get(null);
                JSONObject result = page.apply(params);

                Charset utf8 = StandardCharsets.UTF_8;
                StringBuilder rh = new StringBuilder();
                for ( String h : responses ) {
                    rh.append(h);
                    rh.append("\r\n");
                }
                rh.append("\r\n");
                
                out.write(rh.toString().getBytes(utf8));
                
                out.write(result.toJSON().getBytes(utf8));
                JSONObject ac = (JSONObject) result.getJSON("ac");
                
                String idToken = (String) ac.get("id_token");
                
                out.write(idToken.getBytes(utf8));
                out.write(JWS7515.clientAll(idToken).toJSON().getBytes(utf8));
                out.flush();
            } finally {
                soc.close();
                close();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            // 繋がらない
        }
    }
}
