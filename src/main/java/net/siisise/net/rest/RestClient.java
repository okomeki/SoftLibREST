package net.siisise.net.rest;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import net.siisise.io.FileIO;
import net.siisise.json2.JSON2;
import net.siisise.json2.JSON2Object;
import net.siisise.json2.JSON2Value;
import net.siisise.omap.OMAP;

/**
 * JSONを使うのでSoftLibに置けない仮置き場
 */
public class RestClient {

    private String baseuri;
    
    JSON2Object<String> headers = new JSON2Object();
    
    private final String accessToken;
//    private String accept = "application/json";

    public RestClient(String accessToken) {
        this.accessToken = accessToken;
        headers.put("Accept", "application/json");
        headers.put("Authorization", "Bearer " + accessToken);
    }

    public RestClient(String baseURI, String accessToken) {
        this(accessToken);
        baseuri = baseURI;
    }

    public void setBaseURI(String base) {
        baseuri = base;
    }

    public JSON2Value get(String uri) throws IOException, URISyntaxException {
        return get(uri, JSON2Value.class);
    }

    public JSON2Value get(URI uri) throws IOException {
        return get(uri, JSON2Value.class);
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

        for ( String key : headers.keySet() ) {
            String value = headers.get(key);
            conn.setRequestProperty(key, value);
        }
//        conn.setRequestProperty("Accept", "application/json");
//        if (accessToken != null) {
//            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
//        }
        conn.connect();

        return result(conn, type);
    }

    public JSON2Value post(String uri, String... parameters) throws IOException, URISyntaxException {
        return post(new URI(baseuri + uri), parameters);
    }

    /**
     * POST. ToDo: パラメータのエンコードしてない.
     *
     * @param uri
     * @param parameters エンコードしてない
     * @return JSON
     * @throws IOException
     */
    public JSON2Value post(URI uri, String... parameters) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("POST");
        for ( String key : headers.keySet() ) {
            String value = headers.get(key);
            conn.setRequestProperty(key, value);
        }
//        conn.setRequestProperty("Accept", "application/json");
//        if (accessToken != null) {
//            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
//        }
        if (parameters.length > 0) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameters.length; i += 2) {
                if (sb.length() > 0) {
                    sb.append("&");
                }
                sb.append(parameters[i]);
                sb.append("=");
                sb.append(parameters[i + 1]);
            }
            byte[] utf = sb.toString().getBytes("utf-8");
            conn.setRequestProperty("Content-Length", "" + utf.length);
            OutputStream out = conn.getOutputStream();
            out.write(utf);
            out.flush();
        }

        conn.connect();

        return result(conn, JSON2Value.class);
    }

    /**
     *
     * @param conn
     * @param type 期待する戻り型
     * @return JSON
     * @throws IOException
     */
    private <T> T result(HttpURLConnection conn, Type type) throws IOException {
        byte[] result = FileIO.binRead(conn.getInputStream());
        conn.disconnect();
        return OMAP.valueOf(JSON2.parse(result), type);
//                JSON2.parseWrap(result);
    }
}
