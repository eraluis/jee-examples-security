package cifrado.bloques;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
 
public class CipherAES {
 
    public static void main(String[] args) throws Exception {
    	
    	cipherAES("Prueba de mensaje");
    }
     
    
    static String cipherAES(String mensaje) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    	
    	String algorthm = "AES";    	
    	System.out.println("Cifrado por bloques: "+algorthm);
    	KeyGenerator keyGenerator = KeyGenerator.getInstance(algorthm);
    	
        keyGenerator.init(128);
        Key key = keyGenerator.generateKey();
        //SecretKey key = keyGenerator.generateKey();
        
        Cipher c = Cipher.getInstance("AES");
        c.init( Cipher.ENCRYPT_MODE, key );
        
        byte[] mensajeEnBytes =  mensaje.getBytes();
        final byte[] cifradoEnBytes = c.doFinal( mensajeEnBytes );
        
        String cifrado = new String(cifradoEnBytes);
                
        System.out.println("mensaje: "+ mensaje);
        System.out.println("mensajeEnBytes: "+ mensajeEnBytes);
        System.out.println("cifradoEnBytes: "+ cifradoEnBytes); 
        System.out.println("cifrado: "+ cifrado);
        
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < cifradoEnBytes.length; i++) {
            sb.append( Integer.toString( (cifradoEnBytes[i] & 0xff) + 0x100, 16).substring(1) );
        }
        System.out.println( sb.toString() );
    	
    	return null;
    }
    
}
