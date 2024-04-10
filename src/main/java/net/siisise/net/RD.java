package net.siisise.net;

import java.net.URI;

/**
 * Resource Descriptor.
 * OASIS XRD v1.0
 * RFC 6415 Appendix JRD
 *
 * @param <T> 
 */
public interface RD<T> {

    // Zero or One
    void expires(String date);
    void subject(URI value);

    // Zero or More
    void alias(URI uri);
    void property(URI typeUri, String text);
    void link(String rel, String type, URI href, String template);
    void linkHref(String rel, URI href, String type);
    void linkTemplate(String rel, String template, String type);
    T get();
}
