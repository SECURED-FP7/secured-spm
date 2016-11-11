/**********************************************************************************************
 * Copyright (c) 2016 Politecnico di Torino.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *   - POLITO TorSec Team: Fulvio Valenza, Christian Pitscheider, Cataldo Basile, Marco Vallini 
 *	 - SECURED Team 
 *	 - Corresponding: fulvio.valenza@polito.it, cataldo.basile@polito.it
 ************************************************************************************************/
package main.java.refinement_class;

import static javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI;
import main.java.hspl_class.Mapping;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.UnmarshalException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.ValidationEvent;
import javax.xml.bind.ValidationEventHandler;
import javax.xml.bind.ValidationEventLocator;
import javax.xml.validation.SchemaFactory;

import org.apache.commons.codec.binary.Base64;
import org.kie.api.KieBase;
import org.kie.api.KieServices;
import org.kie.api.builder.KieBuilder;
import org.kie.api.builder.KieFileSystem;
import org.kie.api.builder.Message;
import org.kie.api.builder.Results;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import eu.fp7.secured.spm.h2mservice.impl.H2mserviceImpl;

public class Useful {
    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);

    public static void mashal (Object o,  String xml_file, Class c){

        Marshaller marshaller;
        // create a JAXBContext
        JAXBContext jaxbContext;

        try {
            jaxbContext= JAXBContext.newInstance(c);

            marshaller = jaxbContext.createMarshaller ();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,  new Boolean(true));
            marshaller.marshal(o, new FileOutputStream(xml_file));
        }
        catch(JAXBException e) {
            e.printStackTrace();
            LOG.error(e.toString());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            LOG.error(e.toString());
        }
    }

    public static String mashal2 (Object o, Class c){

		Marshaller marshaller;
		// create a JAXBContext
        JAXBContext jaxbContext;
        String xmlString="";
        
		try {           
			jaxbContext= JAXBContext.newInstance(c);
			marshaller = jaxbContext.createMarshaller ();           
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,  new Boolean(true));
          //  marshaller.marshal(o, new FileOutputStream(xml_file));
            
            StringWriter sw = new StringWriter();
            marshaller.marshal( o, sw);
            xmlString= sw.toString();
        } 
		catch(JAXBException e) {         
            e.printStackTrace();
		}       
		
		return xmlString;
	}
	
    
    public static Object unmashal(String schema_file, String xml_file, Class c){
        Object obj = null;
        try {

            // create a JAXBContext capable of handling classes generated into
            // JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class );

            JAXBContext jc = JAXBContext.newInstance(c );


            // create an Unmarshaller
            Unmarshaller u = jc.createUnmarshaller();

            SchemaFactory sf = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);



            try {

//                LOG.info("\n\n  XX -->> Schema file: " + schema_file);
//                LOG.info("\n\n  XX -->> xml_file file: " + xml_file);
                //++
                javax.xml.validation.Schema schema;
                if (schema_file.contains("/tmp/")){
                    schema =  sf.newSchema(new File(schema_file));
                }else{
                    URL urlSchema = getUrl(H2mserviceImpl.class, schema_file);
//                    LOG.info("\n\n  XX -->> urlSchema: " + urlSchema.getPath());
                    schema =  sf.newSchema(urlSchema);
                }
                //--
                //javax.xml.validation.Schema schema =  sf.newSchema(new File(schema_file));
                // ++


                u.setSchema((javax.xml.validation.Schema) schema);
                u.setEventHandler(  new ValidationEventHandler() {
                    // allow unmarshalling to continue even if there are errors
                    public boolean handleEvent(ValidationEvent ve) {
                        // ignore warnings
                        if (ve.getSeverity() != ValidationEvent.WARNING) {
                            ValidationEventLocator vel = ve.getLocator();
                            System.out.println("Line:Col[" + vel.getLineNumber() +
                                    ":" + vel.getColumnNumber() +
                                    "]:" + ve.getMessage());
                        }
                        return true;
                    }
                }
                        );
            } catch (org.xml.sax.SAXException se) {
                System.out.println("Unable to validate due to following error.");
                se.printStackTrace();
                LOG.error("===>[1]ERROR Unmashaling \n\n" + se.toString());
                LOG.error(Useful.getStackTrace(se));
            } catch (Exception e){
                LOG.error("===>[2]ERROR Unmashaling \n\n" + e.toString());
                LOG.error(Useful.getStackTrace(e));
            }

            if (xml_file.contains("/tmp/")){
                obj = u.unmarshal( new File( xml_file));
            }else{
                URL url_xml_file = getUrl(H2mserviceImpl.class, xml_file);
                LOG.info("\n\n  XX -->> url_xml_file: " + url_xml_file.getPath());
                obj = u.unmarshal(url_xml_file);
            }


            //--
            //obj = u.unmarshal( new File( xml_file));

            //++

            // even though document was determined to be invalid unmarshalling,
            // marshal out result.
            //           System.out.println("");
            //         System.out.println("Still able to marshal invalid document");
            //       javax.xml.bind.Marshaller m = jc.createMarshaller();
            // m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );
            //     m.marshal(poe, System.out);
        } catch( UnmarshalException ue ) {
            // The JAXB specification does not mandate how the JAXB provider
            // must behave when attempting to unmarshal invalid XML data.
            // those cases, the JAXB provider is allowed to terminate the
            // call to unmarshal with an UnmarshalException.
            System.out.println( "Caught UnmarshalException" );
            LOG.error("===>[3]ERROR Unmashaling \n\n" + ue.toString());
        } catch( JAXBException je ) {
            je.printStackTrace();
            LOG.error("===>[4]ERROR Unmashaling \n\n" +je.toString());
            LOG.error(Useful.getStackTrace(je));
        } catch( Exception e){
            LOG.error("===>[5]ERROR Unmashaling \n\n" +e.toString());
            LOG.error(Useful.getStackTrace(e));
        }

        if (obj == null){
            LOG.error("===>[6]ERROR Unmashaling Object NULL");
        }
        return obj;
    }


    public static Object unmashal2(String schema_file, String xml_file, Class c){
        Object obj = null;
        try {

            // create a JAXBContext capable of handling classes generated into
            // JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class );

            JAXBContext jc = JAXBContext.newInstance(c);

            // create an Unmarshaller
            Unmarshaller u = jc.createUnmarshaller();

            SchemaFactory sf = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);

            try {

                javax.xml.validation.Schema schema =  sf.newSchema(new File(schema_file));

                u.setSchema((javax.xml.validation.Schema) schema);
                u.setEventHandler(  new ValidationEventHandler() {
                    // allow unmarshalling to continue even if there are errors
                    public boolean handleEvent(ValidationEvent ve) {
                        // ignore warnings
                        if (ve.getSeverity() != ValidationEvent.WARNING) {
                            ValidationEventLocator vel = ve.getLocator();
                            System.out.println("Line:Col[" + vel.getLineNumber() +
                                    ":" + vel.getColumnNumber() +
                                    "]:" + ve.getMessage());
                        }
                        return true;
                    }
                }
                        );
            } catch (org.xml.sax.SAXException se) {
                System.out.println("Unable to validate due to following error.");
                se.printStackTrace();
                LOG.error(se.toString());
            }

            obj = u.unmarshal( new File( xml_file));



            // even though document was determined to be invalid unmarshalling,
            // marshal out result.
            //           System.out.println("");
            //         System.out.println("Still able to marshal invalid document");
            //       javax.xml.bind.Marshaller m = jc.createMarshaller();
            // m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );
            //     m.marshal(poe, System.out);
        } catch( UnmarshalException ue ) {
            // The JAXB specification does not mandate how the JAXB provider
            // must behave when attempting to unmarshal invalid XML data.
            // those cases, the JAXB provider is allowed to terminate the
            // call to unmarshal with an UnmarshalException.
            System.out.println( "Caught UnmarshalException" );
        } catch( JAXBException je ) {
            je.printStackTrace();
            LOG.error(je.toString());
        }

        return obj;
    }



    public static KieSession build(String s1, String s2) throws Exception {

        KieServices kieServices = KieServices.Factory.get();
        kieServices.newKieClasspathContainer(H2mserviceImpl.class.getClassLoader());
        KieFileSystem kfs = kieServices.newKieFileSystem();
        Thread.currentThread().setContextClassLoader(H2mserviceImpl.class.getClassLoader());

        try {
            URL url = getUrl(H2mserviceImpl.class, s1);
            kfs.write(s2,
                    kieServices.getResources().newInputStreamResource(url.openStream()));

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        KieBuilder kieBuilder = kieServices.newKieBuilder(kfs).buildAll();
        Results results = kieBuilder.getResults();
        if (results.hasMessages(Message.Level.ERROR)) {
            System.out.println(results.getMessages());
            throw new IllegalStateException("### errors ###");
        }

        KieContainer kieContainer = kieServices.newKieContainer(kieServices.getRepository().getDefaultReleaseId());
        KieBase kieBase = kieContainer.getKieBase();
        KieSession ksession = kieContainer.newKieSession();
        return ksession;
    }

    public static  String readFile(String path, Charset encoding) throws IOException{
        //byte[] encoded = Files.readAllBytes(Paths.get(path));
        //return new String(encoded, encoding);
        return new String(readFileAsBytes(H2mserviceImpl.class, path), encoding);
    }

    public static  String readFile_local_tmp(String path, Charset encoding) throws IOException{
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }


    public static boolean  validation (String schema_file, String xml_file){
        Object obj = null;


        // create a JAXBContext capable of handling classes generated into
        // JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class );

        JAXBContext jc;
        try {
            jc = JAXBContext.newInstance( );



            // create an Unmarshaller
            Unmarshaller u = jc.createUnmarshaller();

            SchemaFactory sf = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);

            try {

                javax.xml.validation.Schema schema =  sf.newSchema(new File(schema_file));

                u.setSchema((javax.xml.validation.Schema) schema);
                u.setEventHandler(  new ValidationEventHandler() {
                    // allow unmarshalling to continue even if there are errors
                    public boolean handleEvent(ValidationEvent ve) {
                        // ignore warnings
                        if (ve.getSeverity() != ValidationEvent.WARNING) {
                            ValidationEventLocator vel = ve.getLocator();
                            System.out.println("Line:Col[" + vel.getLineNumber() +
                                    ":" + vel.getColumnNumber() +
                                    "]:" + ve.getMessage());
                        }
                        return true;
                    }
                }
                        );
            } catch (org.xml.sax.SAXException se) {
                System.out.println("Unable to validate due to following error.");
                se.printStackTrace();
                LOG.error(se.toString());
            }

        } catch (JAXBException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            LOG.error(e.toString());
        }


        return true;

    }


    static public byte[] readFileAsBytes(Class c, String fileName) throws IOException {
        InputStream inStream = new java.io.BufferedInputStream(c.getClassLoader().getResourceAsStream(fileName));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int nbytes = 0;
        byte[] buffer = new byte[100000];

        try {
            while ((nbytes = inStream.read(buffer)) != -1) {
                out.write(buffer, 0, nbytes);
            }
            return out.toByteArray();
        } finally {
            if (inStream != null) {
                inStream.close();
            }
            if (out != null) {
                out.close();
            }
        }
    }

    static public InputStream getInputStream(Class c, String fileName) throws IOException {
        return new java.io.BufferedInputStream(c.getClassLoader().getResourceAsStream(fileName));
    }

    static public URL getUrl(Class c, String fileName) throws Exception {
        return c.getClassLoader().getResource(fileName);
    }

    static public String getStackTrace(Throwable aThrowable) {
        Writer result = new StringWriter();
        PrintWriter printWriter = new PrintWriter(result);
        aThrowable.printStackTrace(printWriter);
        return result.toString();
    }

    
    static public String encode64(String s){
    	
    	byte[]   bytesEncoded = Base64.encodeBase64(s .getBytes());
    	return new String (bytesEncoded);
    	
    			 
    }
    
    static public String dencode64(String s){
    	
    	
    	byte[] valueDecoded= Base64.decodeBase64(s.getBytes());
    	return new String (valueDecoded);
    	
    }
    

}
