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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

// https://stackoverflow.com/questions/40965378/is-there-a-good-example-out-there-for-xml-sign-with-xades-epes-in-java
// http://camel.apache.org/xml-security-component.html
// https://github.com/apache/camel/blob/master/components/camel-xmlsecurity/src/test/java/org/apache/camel/component/xmlsecurity/XAdESSignaturePropertiesTest.java
// http://www.facturae.gob.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf
// http://www.etsi.org/deliver/etsi_ts%5C101900_101999%5C101903%5C01.04.02_60%5Cts_101903v010402p.pdf
// http://geminisecurity.com/wp-content/uploads/tools/xades-overview.pdf
public class DigSig_JSR106 {
	
	//private static final String RUTA_CERTIFICADO ="src/main/resources/certificados/x509/x509-personal.crt";
	//private static final String RUTA_LLAVE_PRIVADA_PKCS8 ="src/main/resources/certificados/x509/rsa-key-1.der";	
	private static final String RUTA_PKCS12 ="src/main/resources/certificados/x509/persona_juridica_pruebas_vigente.p12";
	private static final String DOCUMENTO_XML ="src/main/resources/datos/documentos/libro1.xml";
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
		        
        System.out.println("\n********** Paso 3: Llave Pública **********");
        //https://stackoverflow.com/questions/20897065/how-to-get-exponent-and-modulus-value-of-rsa-public-key-from-pfx-file-pem-file-i
        
        PublicKey publicKey = x509.getPublicKey();        
        if(publicKey instanceof RSAPublicKey ){
        	RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        	System.out.println("Public Exponent: " + rsaPublicKey.getPublicExponent().toString(16));
        	System.out.println("Modulus: "+ rsaPublicKey.getModulus().toString(16));
            
        }        
        
        System.out.println("\n********** Paso 4: Contexto de firma XML **********");
	    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
	    
	    /*
	     * Crear una referencia al documento.
	     * En este caso se va a firmar el documento completo (URI = "")
	     * Se especifica SHA1 como algoritmo de resumen y
	     * como  transformacion "ENVELOPED" 
	     */
	    Reference reference = signatureFactory.newReference
	            ("",
	             signatureFactory.newDigestMethod(DigestMethod.SHA1, null),
	             Collections.singletonList
	             	(signatureFactory.newTransform(
	             			Transform.ENVELOPED,
	             			(TransformParameterSpec) null
	             			)
	            	),
	             null,
	             null
	             );
	    
	    
	    SignedInfo signedInfo = signatureFactory.newSignedInfo(
	    		
	    		signatureFactory.newCanonicalizationMethod
	                (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null),	             
	            signatureFactory.newSignatureMethod
	            	(SignatureMethod.RSA_SHA1 , null),
	            Collections.singletonList(reference)
	    	);
	    	    	    	   
	    KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        
	    /* Prueba 2-oct-2017 */
	    //KeyValue keyValue = keyInfoFactory.newKeyValue( x509.getPublicKey() );
        //KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList( keyValue ));
        
        /* Prueba 2-oct-2017 */
        List<X509Certificate> x509list = new ArrayList<>();        
        x509list.add(x509);
        X509Data x509Data = keyInfoFactory.newX509Data(x509list);
                       
        List<X509Data> items = new ArrayList<>();
        items.add(x509Data);
                
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(items);
        
        // Crear contexto de firma
        DocumentBuilderFactory documentBuilder = DocumentBuilderFactory.newInstance();
        documentBuilder.setNamespaceAware(true);
        Document xmlDocument = documentBuilder.newDocumentBuilder().parse(new FileInputStream( DOCUMENTO_XML ));
	    		          
        DOMSignContext domSingContext = new DOMSignContext
        		// (privateKey, xmlDocument.getDocumentElement() ); Poner la firma sobre raiz del documento
        		(privateKey, xmlDocument.getElementsByTagNameNS("ns:libro:extension", "extentsion").item(1) );

        // Crear XMLSignature y firmar documento.
        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);        
        signature.sign(domSingContext);
        
        // Mostrar salida
        OutputStream os;
        if (args.length >= 1) {
           os = new FileOutputStream(args[0]);
        } else {
           os = System.out;
        }
        
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(xmlDocument), new StreamResult(os));
        
	}

}
