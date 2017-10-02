package firmas;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.camel.CamelContext;
import org.apache.camel.RoutesBuilder;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.xmlsecurity.api.DefaultKeyAccessor;
import org.apache.camel.component.xmlsecurity.api.DefaultXAdESSignatureProperties;
import org.apache.camel.component.xmlsecurity.api.XAdESEncapsulatedPKIData;
import org.apache.camel.component.xmlsecurity.api.XAdESSignatureProperties;
import org.apache.camel.impl.DefaultCamelContext;
import org.w3c.dom.Document;

// https://stackoverflow.com/questions/40965378/is-there-a-good-example-out-there-for-xml-sign-with-xades-epes-in-java
// http://camel.apache.org/xml-security-component.html
// https://github.com/apache/camel/blob/master/components/camel-xmlsecurity/src/test/java/org/apache/camel/component/xmlsecurity/XAdESSignaturePropertiesTest.java
// http://www.facturae.gob.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf
// http://www.etsi.org/deliver/etsi_ts%5C101900_101999%5C101903%5C01.04.02_60%5Cts_101903v010402p.pdf
// http://geminisecurity.com/wp-content/uploads/tools/xades-overview.pdf
public class XAdES_Camel_v1 {
	
	//private static final String RUTA_CERTIFICADO ="src/main/resources/certificados/x509/x509-personal.crt";
	//private static final String RUTA_LLAVE_PRIVADA_PKCS8 ="src/main/resources/certificados/x509/rsa-key-1.der";	
	private static final String RUTA_PKCS12 ="src/main/resources/certificados/x509/persona_juridica_pruebas_vigente.p12";
	private static final String DOCUMENTO_XML ="src/main/resources/documentos/libro1.xml";
	private static final String PASSWORD = "persona_juridica_pruebas";
	
	
	public static void main(String[] args) throws Exception {
		
		/*
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	    FileInputStream fis = new FileInputStream ( RUTA_CERTIFICADO );
	    X509Certificate x509 = (X509Certificate) certificateFactory.generateCertificate(fis);
	    
		// Obtención de llaves privada y publica	    
	    byte[] keyBytes = Files.readAllBytes(Paths.get(RUTA_LLAVE_PRIVADA_PKCS8));
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory keyfactory = KeyFactory.getInstance("RSA");
	    PrivateKey privateKey = keyfactory.generatePrivate(spec);
	    */
		
		InputStream stream = new FileInputStream(RUTA_PKCS12);		
	    KeyStore p12 = KeyStore.getInstance("PKCS12");	    
	    p12.load(stream, PASSWORD.toCharArray());	    
	    
	    System.out.println("********** Paso 1: Llave Privada **********");
	    // https://stackoverflow.com/questions/18621508/getting-a-privatekey-object-from-a-p12-file-in-java
	    
	    PrivateKey privateKey = (PrivateKey) p12.getKey("usuario de pruebas", PASSWORD.toCharArray());	    
	    System.out.println("privateKey.getAlgorithm: "+privateKey.getAlgorithm() );
	    System.out.println("privateKey.getFormat: "+privateKey.getFormat() );	    
	    System.out.println("privateKey.getEncoded: "+privateKey.getEncoded() );
	    
	    System.out.println("\n********** Paso 2: Certificado x509 **********");	    
	    X509Certificate x509 = (X509Certificate) p12.getCertificate("Usuario de Pruebas");
	    
	    Principal subject = x509.getSubjectDN();
	    String subjectArray[] = subject.toString().split(",");
        for (String s : subjectArray) {
            String[] str = s.trim().split("=");
            String k = str[0];
            String value = str[1];
            System.out.println(k + " - " + value);
        }
        
	    /*
	    Enumeration<String> e = p12.aliases();	    
	    while (e.hasMoreElements()) {
            String alias = e.nextElement();
            X509Certificate c = (X509Certificate) p12.getCertificate(alias);
            Principal subject = c.getSubjectDN();
            String subjectArray[] = subject.toString().split(",");
            System.out.println("********** Alias: "+alias);
            for (String s : subjectArray) {
                String[] str = s.trim().split("=");
                String key = str[0];
                String value = str[1];
                System.out.println(key + " - " + value);
            }
	    }
        */
		        
        System.out.println("\n********** Paso 4: Llave Pública **********");
        //https://stackoverflow.com/questions/20897065/how-to-get-exponent-and-modulus-value-of-rsa-public-key-from-pfx-file-pem-file-i
        
        PublicKey publicKey = x509.getPublicKey();        
        if(publicKey instanceof RSAPublicKey ){
        	RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        	System.out.println("Public Exponent: " + rsaPublicKey.getPublicExponent().toString(16));
        	System.out.println("Modulus: "+ rsaPublicKey.getModulus().toString(16));
            
        }        
        
        System.out.println("\n********** Paso 4: Contexto de firma XML XAdES **********");
        
        CamelContext camelContext = new DefaultCamelContext();        

        // add our route to the CamelContext
        camelContext.addRoutes(new RouteBuilder() {
            public void configure() {
//                from("file:data/inbox?noop=true").to("file:data/outbox");
            	from("direct:enveloping").to("xmlsecurity:sign://enveloping?keyAccessor=#accessor",
                        "xmlsecurity:verify://enveloping?keySelector=#selector","mock:result");
            }
        });
        
        
        
       // SomeEndpoint endpoint = camelContext.getEndpoint("someURI", SomeEndpoint.class); 
        //endpoint.setSomething("aValue");
        
        
        
        DefaultKeyAccessor accessor = new DefaultKeyAccessor();
        accessor.setKeyStore(p12);
        accessor.setPassword(PASSWORD);
        accessor.setAlias("usuario de pruebas"); // signer key alias
        
	   
        DefaultXAdESSignatureProperties props = new DefaultXAdESSignatureProperties();
        props.setNamespace("http://uri.etsi.org/01903/v1.3.2#"); // sets the namespace for the XAdES elements; the namspace is related to the XAdES version, default value is "http://uri.etsi.org/01903/v1.3.2#", other possible values are "http://uri.etsi.org/01903/v1.1.1#" and "http://uri.etsi.org/01903/v1.2.2#"
        props.setPrefix("etsi"); // sets the prefix for the XAdES elements, default value is "etsi"
        
        // signing certificate
        props.setKeystore(p12);
        props.setAlias("usuario de pruebas"); // specify the alias of the signing certificate in the keystore = signer key alias
        props.setDigestAlgorithmForSigningCertificate(DigestMethod.SHA256); // possible values for the algorithm are "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512", default value is "http://www.w3.org/2001/04/xmlenc#sha256"
        props.setSigningCertificateURIs(Collections.singletonList("http://certuri"));
        
        // signing time
        props.setAddSigningTime(true);
        
     // policy
        props.setSignaturePolicy(XAdESSignatureProperties.SIG_POLICY_EXPLICIT_ID);
        // also the values XAdESSignatureProperties.SIG_POLICY_NONE ("None"), and XAdESSignatureProperties.SIG_POLICY_IMPLIED ("Implied")are possible, default value is XAdESSignatureProperties.SIG_POLICY_EXPLICIT_ID ("ExplicitId")
        // For "None" and "Implied" you must not specify any further policy parameters
        props.setSigPolicyId("urn:oid:1.2.840.113549.1.9.16.6.1");
        props.setSigPolicyIdQualifier("OIDAsURN"); //allowed values are empty string, "OIDAsURI", "OIDAsURN"; default value is empty string
        props.setSigPolicyIdDescription("invoice version 3.1");
        props.setSignaturePolicyDigestAlgorithm(DigestMethod.SHA256);// possible values for the algorithm are "http://www.w3.org/2000/09/xmldsig#sha1", http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512", default value is http://www.w3.org/2001/04/xmlenc#sha256"
        props.setSignaturePolicyDigestValue("Ohixl6upD6av8N7pEvDABhEL6hM=");
        // you can add  qualifiers for the signature policy either by specifying text or an XML fragment with the root element "SigPolicyQualifier" 
        props.setSigPolicyQualifiers(Arrays
            .asList(new String[] {
                "<SigPolicyQualifier xmlns=\"http://uri.etsi.org/01903/v1.3.2#\"><SPURI>http://test.com/sig.policy.pdf</SPURI><SPUserNotice><ExplicitText>display text</ExplicitText>"
                    + "</SPUserNotice></SigPolicyQualifier>", "category B" }));
        props.setSigPolicyIdDocumentationReferences(Arrays.asList(new String[] {"http://test.com/policy.doc.ref1.txt",
            "http://test.com/policy.doc.ref2.txt" }));
  
        // production place
        props.setSignatureProductionPlaceCity("Munich");
        props.setSignatureProductionPlaceCountryName("Germany");
        props.setSignatureProductionPlacePostalCode("80331");
        props.setSignatureProductionPlaceStateOrProvince("Bavaria");
  
        //role
        // you can add claimed roles either by specifying text or an XML fragment with the root element "ClaimedRole" 
        props.setSignerClaimedRoles(Arrays.asList(new String[] {"test",
            "<a:ClaimedRole xmlns:a=\"http://uri.etsi.org/01903/v1.3.2#\"><TestRole>TestRole</TestRole></a:ClaimedRole>" }));
        props.setSignerCertifiedRoles(Collections.singletonList(new XAdESEncapsulatedPKIData("Ahixl6upD6av8N7pEvDABhEL6hM=",
            "http://uri.etsi.org/01903/v1.2.2#DER", "IdCertifiedRole")));
  
        // data object format
        props.setDataObjectFormatDescription("invoice");
        props.setDataObjectFormatMimeType("text/xml");
        props.setDataObjectFormatIdentifier("urn:oid:1.2.840.113549.1.9.16.6.2");
        props.setDataObjectFormatIdentifierQualifier("OIDAsURN"); //allowed values are empty string, "OIDAsURI", "OIDAsURN"; default value is empty string
        props.setDataObjectFormatIdentifierDescription("identifier desc");
        props.setDataObjectFormatIdentifierDocumentationReferences(Arrays.asList(new String[] {
            "http://test.com/dataobject.format.doc.ref1.txt", "http://test.com/dataobject.format.doc.ref2.txt" }));
  
        //commitment
        props.setCommitmentTypeId("urn:oid:1.2.840.113549.1.9.16.6.4");
        props.setCommitmentTypeIdQualifier("OIDAsURN"); //allowed values are empty string, "OIDAsURI", "OIDAsURN"; default value is empty string
        props.setCommitmentTypeIdDescription("description for commitment type ID");
        props.setCommitmentTypeIdDocumentationReferences(Arrays.asList(new String[] {"http://test.com/commitment.ref1.txt",
            "http://test.com/commitment.ref2.txt" }));
        // you can specify a commitment type qualifier either by simple text or an XML fragment with root element "CommitmentTypeQualifier"
        props.setCommitmentTypeQualifiers(Arrays.asList(new String[] {"commitment qualifier",
            "<c:CommitmentTypeQualifier xmlns:c=\"http://uri.etsi.org/01903/v1.3.2#\"><C>c</C></c:CommitmentTypeQualifier>" }));
  

        
        
	}

}
