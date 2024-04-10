package net.siisise.net;

import java.net.URI;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import net.siisise.xml.TrXML;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Extensible Resource Descriptor. OASIS XRD-1.0 RFC 6415 WebFinger でつかうやつ
 * SoftLibXML へ持っていくかもしれず XRDSの中にあったのは違う?
 * 
 * OASIS XRD-1.0
 */
public class XRD implements RD<Document> {

    static final String xrdns = "http://docs.oasis-open.org/ns/xri/xrd-1.0";
    static final String xsins = "http://www.w3.org/2001/XMLSchema-instance";

    static DOMImplementation dom;

    Document doc;
    Element root;

    /**
     *
     * @param doc XRDつくる空document namespaceが使えること
     */
    public XRD(Document doc) {
        this.doc = doc;
        root = doc.createElementNS(xrdns, "XRD");
        root.setAttribute("xmlns", xrdns);
        doc.appendChild(root);
    }

    public static XRD create() {
        if (dom == null) {
            DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
            df.setNamespaceAware(true);
            try {
                DocumentBuilder db = df.newDocumentBuilder();
                dom = db.getDOMImplementation();
            } catch (ParserConfigurationException ex) {
                throw new IllegalStateException(ex);
            }
        }
        Document doc = dom.createDocument(xrdns, "XRD", null);
        return new XRD(doc);
    }

    /**
     * 有効期限.
     *
     * @param date YYYY-MM-DDThh-mm-ssZ 整形済み
     */
    @Override
    public void expires(String date) {
        NodeList els = doc.getElementsByTagNameNS(xrdns, "Expires");
        if (els.getLength() > 0) {
            throw new IllegalStateException("Expires element already exists");
        }
        Element expiresElement = doc.createElementNS(xrdns, "Expires");
        expiresElement.appendChild(doc.createTextNode(date));
        doc.appendChild(expiresElement);
        throw new UnsupportedOperationException("yet.");
    }

    @Override
    public void subject(URI subject) {
        NodeList els = doc.getElementsByTagNameNS(xrdns, "Subject");
        if (els.getLength() > 0) {
            throw new IllegalStateException("Subject element already exists");
        }
        Element subjectElement = doc.createElementNS(xrdns, "Subject");
        subjectElement.appendChild(doc.createTextNode(subject.toString()));
        root.appendChild(subjectElement);
    }

    @Override
    public void alias(URI uri) {
        Element alias = doc.createElement("Alias");
        alias.appendChild(doc.createTextNode(uri.toString()));
        root.appendChild(alias);
    }

    @Override
    public void property(URI typeUri, String text) {
        Element prop = doc.createElement("Property");
        prop.setAttribute("type", typeUri.toString() );
        if (text == null) {
            prop.setAttributeNS(xsins, "nil", "true");
        } else {
            prop.appendChild(doc.createTextNode(text));
        }
        root.appendChild(prop);
    }
    
    @Override
    public void link(String rel, String type, URI href, String template) {
        Element link = doc.createElement("Link");
        if ( rel != null ) {
            link.setAttribute("rel", rel.toString());
        }
        if ( type != null ) {
            link.setAttribute("type", type);
        }
        if ( href != null ) {
            link.setAttribute("href", href.toString());
        }
        if ( template != null ) {
            link.setAttribute("template", template);
        }
        root.appendChild(link);
    }

    @Override
    public void linkHref(String rel, URI href, String type) {
        link(rel, type, href, null);
    }

    @Override
    public void linkTemplate(String rel, String template, String type) {
        link(rel, type, null, template);
    }

    @Override
    public Document get() {
        return doc;
    }

    @Override
    public String toString() {
        try {
            return TrXML.plane(doc);
        } catch (TransformerException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
