package eu.securedfp7.m2lservice.plugin;

// For validating the XMLSchema
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.*;
import org.xml.sax.SAXException;
import java.net.*;
import java.io.*;

public class Tester {

    // For testing
    public static void main( final String[] args ) {
        System.out.println( "################################");
        System.out.println( "Tester.");
        String validateRes = validateSchemaReturnError(args[ 0 ]);
        if(validateRes != null){
              System.out.println("##Oops! Your  MSPL (" + args[ 0 ] + ") does not validate with the schema, reason: \n" + validateRes); 
        }else{
              System.out.println("##Great! Your  MSPL (" + args[ 0 ] + " is well formed!");
        }    
        System.out.println( "################################");
        
        System.out.println( "input: " + args[ 0 ] );
        System.out.println( "output: " + args[ 1 ] );
        final M2LPlugin plugin = new M2LPlugin();
        final int status = plugin.getConfiguration( args[ 0 ], args[ 1 ] );
        System.out.println( "status: " + status );
    }
    
    private static String validateSchemaReturnError(String MSPLFileName) {
        String ret = null;
        Source xmlFile = new StreamSource(new File(MSPLFileName));
        SchemaFactory schemaFactory = SchemaFactory
            .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Source schemaFileValidate;
            Schema schema;
            Validator validator = null;
        try {
             // NOTE: assumes you run this from M2LPluginBro folder, modify if needed.
             schemaFileValidate = new StreamSource(new File("./schema/MSPL_XML_Schema.xsd"));
             schema = schemaFactory.newSchema(schemaFileValidate);
             validator = schema.newValidator();
        } catch (SAXException e) {
            e.printStackTrace();
        }
        try {
          validator.validate(xmlFile);
          //System.out.println("####" + xmlFile.getSystemId() + " is valid"); 
        } catch (SAXException e) {
          //System.out.println(xmlFile.getSystemId() + " is NOT valid");
          ret = e.getLocalizedMessage();
        }catch ( final IOException e) {
            e.printStackTrace();
        } 
        
        return ret;
    }
}
