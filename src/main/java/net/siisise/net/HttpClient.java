package net.siisise.net;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 */
public class HttpClient {

    protected String baseuri;
    protected Map<String,String> headers = new LinkedHashMap<>();
    
    public void setBaseURI(String base) {
        baseuri = base;
    }
}
