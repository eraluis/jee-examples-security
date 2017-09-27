package certificados;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.xmlsecurity.api.DefaultKeyAccessor;
import org.apache.camel.component.xmlsecurity.api.XmlSignatureException;

public class XAdESv2 {
	
	private static final String RUTA_PKCS12 ="src/main/resources/certificados/x509/persona_juridica_pruebas_vigente.p12";
	private static final String DOCUMENTO_XML ="src/main/resources/documentos/libro1.xml";
	private static final String PASSWORD = "persona_juridica_pruebas";
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		
		InputStream stream = new FileInputStream(RUTA_PKCS12);		
	    KeyStore p12 = KeyStore.getInstance("PKCS12");	    
	    p12.load(stream, PASSWORD.toCharArray());	
	    
		DefaultKeyAccessor accessor = new DefaultKeyAccessor();
        accessor.setKeyStore(p12);
        accessor.setPassword(PASSWORD);
        accessor.setAlias("usuario de pruebas"); // signer key alias
        

	}
	

    protected RouteBuilder[] createRouteBuilders() throws Exception {
        return new RouteBuilder[] { new RouteBuilder() {
            public void configure() throws Exception {
                onException(XmlSignatureException.class).handled(true).to("mock:exception");
                from("direct:enveloped")
                        .to("xmlsecurity:sign:xades?keyAccessor=#keyAccessorDefault&properties=#xmlSignatureProperties&parentLocalName=root&parentNamespace=http://test/test")
                        .to("mock:result");
            }
        }, new RouteBuilder() {
            public void configure() throws Exception {
                onException(XmlSignatureException.class).handled(true).to("mock:exception");
                from("direct:enveloping").to("xmlsecurity:sign:xades?keyAccessor=#keyAccessorDefault&properties=#xmlSignatureProperties")
                        .to("mock:result");
            }
        }, new RouteBuilder() {
            public void configure() throws Exception {
                onException(XmlSignatureException.class).handled(true).to("mock:exception");
                from("direct:emptySignatureId").to(
                        "xmlsecurity:sign:xades?keyAccessor=#keyAccessorDefault&properties=#xmlSignatureProperties&signatureId=").to(
                        "mock:result");
            }
        }, new RouteBuilder() {
            public void configure() throws Exception {
                onException(Exception.class).handled(false).to("mock:exception");
                from("direct:detached").to(
                        "xmlsecurity:sign:detached?keyAccessor=#keyAccessorDefault&xpathsToIdAttributes=#xpathsToIdAttributes&"//
                                + "schemaResourceUri=org/apache/camel/component/xmlsecurity/Test.xsd&properties=#xmlSignatureProperties")
                        .to("mock:result");
            }
        } };
}

}
