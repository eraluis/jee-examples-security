package camel;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;

public class XMLReaderProcessor implements Processor {
	
	@Override
	public void process(Exchange exchange) throws Exception {
								 
		String myString = exchange.getIn().getBody(String.class);
//		File documentoXML = exchange.getIn().getBody(File.class);
//		System.out.println( documentoXML.getName() );
				
        String[] myArray = myString.split( System.getProperty("line.separator") );
        StringBuffer sb = new StringBuffer();
        for (String s : myArray) {
        	System.out.println("String: "+ s);
            sb.append(s).append( System.getProperty("line.separator") );
        }
        
        System.out.println("Proceso finalizado.");
        exchange.getIn().setBody(sb.toString());
		
	}
	
}
