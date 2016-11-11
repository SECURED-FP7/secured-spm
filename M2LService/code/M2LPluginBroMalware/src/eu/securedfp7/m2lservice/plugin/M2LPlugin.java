package eu.securedfp7.m2lservice.plugin;

import java.util.List;
import java.util.LinkedList;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.LinkedList;

import java.lang.IllegalStateException;
import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonWriterFactory;
import javax.json.JsonWriter;
import javax.json.JsonException;

import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.commons.codec.binary.Base64;

/**
 * Provides the Medium to Low Level (M2L) translation service for BroNSM.
 *
 * @author VTT Technical Research Centre of Finland Ltd
 * @version 0.2 2016/03/22
 */

public class M2LPlugin {
    private static String securityControl = "BroNSM";
    private static String version = "0.2";
    private static String devlopedBy = "VTT Technical Research Centre of Finland Ltd";
    private static String providedBy = "SECURED project";

    public M2LPlugin() {
    }

    public String getType() {
        return this.securityControl;
    }

    public String getVersion() {
        return this.version;
    }

    public String developedBy() {
        return this.devlopedBy;
    }

    public String providedBy() {
        return this.providedBy;
    }
    
    /**
     * Perform the translation
     * 
     * @param MSPLFileName
     *            : MSPL file name
     * @param securityControlFileName
     *            : output file name
     * @return 0 if OK, -1 if can't read MSPLFileName IOException, -2 if BadConfigException and -3 if JsonException occurs.
     */
    public int getConfiguration( String MSPLFileName,
                                 String securityControlFileName) {
        int result = 1;
        FileInputStream in = null;
        FileOutputStream out = null;

        try {
            // Check if the input file is encoded as Base64
            // TODO: We simply decode into a temp file and pass that to MSPLParser, should refactor...
            // Note: We does not delete the temp file.
            boolean isBase64Encoded = false;
            try {
                final String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
                if(Base64.isBase64(inputString.getBytes())){
                    isBase64Encoded = true;
                    FileOutputStream tempOut = null;
                    try {
                        MSPLFileName = MSPLFileName + ".tmp";
                        tempOut = new FileOutputStream(MSPLFileName);
                        final byte[] decodedBytes = Base64.decodeBase64(inputString.getBytes());
                        tempOut.write(decodedBytes);
                    } catch ( final IOException e) {
                        e.printStackTrace();
                    } finally {
                        if( tempOut != null ) {
                            try {
                                tempOut.close();
                            } catch ( final IOException e ) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } catch ( final IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }

            System.out.println( "isBase64Encoded: " + isBase64Encoded );
            // TODO: fix below.
            // replace quotations and \n from the input files
            try {
                String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
                inputString = inputString.replace("\\\"", "\"");
                inputString = inputString.replace("\\n", "");
                FileOutputStream outCleaned = new FileOutputStream(MSPLFileName);
                outCleaned.write(inputString.getBytes());
                outCleaned.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            
            // Do the actual M2L -> Bro JSON config conversion
            in  = new FileInputStream( MSPLFileName );
            out = new FileOutputStream( securityControlFileName );
            final List< Rule > rules = new LinkedList< Rule >();
            final MSPLParser parser = new MSPLParser();

            parser.parse( in, rules );
            ConfigWriter.write( out, rules );

            // If the input file is encoded in base64 we need to convert the output file to base64
            // Simple write the config again encoded to base64
            // TODO: Modify ConfigWriter to write base64, if needed.
            if(isBase64Encoded){
                FileOutputStream outB64 = null;
                try {
                    final String inputString = new String(Files.readAllBytes(Paths.get(securityControlFileName)));
                    outB64 = new FileOutputStream(securityControlFileName);
                    final byte[] encodedBytes = Base64.encodeBase64(inputString.getBytes());
                    outB64.write(encodedBytes);
                } catch ( final IOException e) {
                    e.printStackTrace();
                } finally {
                    if( outB64 != null ) {
                        try {
                            outB64.close();
                        } catch ( final IOException e ) {
                            e.printStackTrace();
                        }
                    }
                }
            }
            result = 0;

        } catch ( final IOException e ) {
            result = -1;
            e.printStackTrace();
        } catch ( final BadConfigException e ) {
            result = -2;
            e.printStackTrace();
            System.out.println("Booyah! No can do..Just crash?");
        } catch ( final JsonException e ) {
            result = -3;
            e.printStackTrace();
        } finally {
            if ( in != null ) {
                try {
                    in.close();
                } catch ( final IOException e ) {
                    e.printStackTrace();
                }
            }
            if ( out != null ) {
                try {
                    out.close();
                } catch ( final IOException e ) {
                    e.printStackTrace();
                }
            }
        }

        // TODO: What do we return in case of an exception?
        return result;
    }
}
