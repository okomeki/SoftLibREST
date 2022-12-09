package net.siisise.net.rest;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.siisise.io.FileIO;
import net.siisise.net.HttpClient;
import net.siisise.json.bind.OMAP;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * JSONを使うのでSoftLibに置けない仮置き場
 */
public class RestClient extends HttpClient {

    public RestClient(String accessToken) {
        headers.put("Accept", "application/json");
        if ( accessToken != null ) {
            headers.put("Authorization", "Bearer " + accessToken);
        } else {
            headers.remove("Authorization");
        }
    }

    public RestClient(String baseURI, String accessToken) {
        this(accessToken);
        baseuri = baseURI;
    }
    
    /**
     * ToDo: escape
     * @param uri
     * @param nv
     * @return 
     */
    public static URI param(String uri, String... nv) {
        StringBuilder u = new StringBuilder(uri);
        for ( int i = 0; i < nv.length; i+=2) {
            u.append(i == 0 ? "?" : "&");
            u.append(nv[i]);
            u.append("=");
            try {
                u.append(URLEncoder.encode(nv[i+1],"utf-8"));
            } catch (UnsupportedEncodingException ex) {
                // ない
            }
        }
        return URI.create(u.toString());
    }

    public <T> T get(String uri) throws IOException, URISyntaxException {
        return get(uri, JSONValue.class);
    }

    public <T> T get(URI uri) throws IOException {
        return get(uri, JSONValue.class);
    }

    /**
     * fieldから型情報を取得してその形で戻り値を返す
     *
     * @param <T>
     * @param url
     * @param field 代入するフィールド ここから型情報を取得する
     * @return
     * @throws IOException
     * @throws URISyntaxException
     */
    public <T> T get(String url, Field field) throws IOException, URISyntaxException {
        return get(url, field.getGenericType());
    }

    /**
     *
     * @param <T>
     * @param url
     * @param genType 期待する戻り型
     * @return
     * @throws IOException
     * @throws URISyntaxException
     */
    public <T> T get(String url, Type genType) throws IOException, URISyntaxException {
        return get(new URI(baseuri + url), genType);
    }

    /**
     * HTTP GET パラメータ未対応
     *
     * @param <T>
     * @param uri
     * @param type 期待する戻り型
     * @return JSON固定 bindとかしない
     * @throws IOException
     */
    public <T> T get(URI uri, Type type) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();

        headers.forEach((key, val) -> conn.setRequestProperty(key, val) );

        return result(conn, type);
    }

    public JSONValue post(String uri, Map<String, String> paramMap) throws IOException, URISyntaxException {
        return post(new URI(baseuri + uri), paramMap);
    }

    public JSONValue post(String uri, String... parameters) throws IOException, URISyntaxException {
        return post(new URI(baseuri + uri), parameters);
    }

    public JSONValue post(URI uri, Map<String, String> paramMap) throws IOException {
        List<String> params = new ArrayList<>();
        paramMap.forEach((key, val) -> {
            params.add(key);
            params.add(val);
        });
        return post(uri, params.toArray(new String[0]));
    }

    /**
     * POST. application/x-www-form-urlencoded
     *
     * @param uri
     * @param parameters エンコードしてない
     * @return JSON
     * @throws IOException
     */
    public JSONValue post(URI uri, String... parameters) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("POST");
        headers.forEach((key, val) -> conn.setRequestProperty(key, val));

        if (parameters.length > 0) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameters.length; i += 2) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(percentEncode(parameters[i]));
                sb.append('=');
                sb.append(percentEncode(parameters[i + 1]));
            }
            byte[] utf = sb.toString().getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", "" + utf.length);
            OutputStream out = conn.getOutputStream();
            out.write(utf);
            out.flush();
        }

        return result(conn, JSONValue.class);
    }

    /**
     * percent-encoding application/x-www-form-urlencoded 専用 RFC 3986 Section
     * 2.1. RFC 7xxx
     * https://developer.mozilla.org/ja/docs/Glossary/percent-encoding
     * をUTF-8に対応してみたら
     *
     * @param src
     * @return
     */
    private static String percentEncode(String src) {
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

    /**
     *
     * @param conn
     * @param type 期待する戻り型
     * @return JSON
     * @throws IOException
     */
    private <T> T result(HttpURLConnection conn, Type type) throws IOException {
        conn.connect();
        // conn.getResponseCode();
        String contentType = conn.getContentType();
        byte[] result = FileIO.binRead(conn.getInputStream());
        conn.disconnect();
        return OMAP.valueOf(JSON.parse(result), type);
//                JSON.parseWrap(result);
    }
}
