package camel;

import org.apache.camel.CamelContext;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.impl.DefaultCamelContext;

public class CamelXMLDigSigner {
	
	public static void main(String args[]) throws Exception {

        CamelContext context = new DefaultCamelContext();

        context.addRoutes(new RouteBuilder() {
        	
        	@Override
            public void configure() {
                from("file:src/main/resources/datos/documentos?noop=true").process(new SignerProcessor()).to("file:src/main/resources/datos/firmados/digsig");
            }
        });

        // start the route and let it do its work
        context.start();
        Thread.sleep(10000);

        // stop the CamelContext
        context.stop();

	}

}
