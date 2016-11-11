package eu.securedfp7.m2lservice.plugin;

import java.util.List;
import java.util.LinkedList;
import java.lang.IllegalStateException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.json.JsonArrayBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonWriterFactory;
import javax.json.JsonWriter;
import javax.json.JsonException;

class ConfigWriter {

    public static void write( OutputStream out, List< Rule > rules ) throws JsonException {

        try {
            final JsonBuilderFactory factory = Json.createBuilderFactory( null );
            final JsonObjectBuilder builder  = factory.createObjectBuilder();

            final JsonArrayBuilder ruleBuilder = factory.createArrayBuilder();
            for ( final Rule rule : rules ) {
                ruleBuilder.add( rule.toJson( factory ) );
            }
            builder.add( "rules", ruleBuilder );
            final JsonObject object = builder.build();
            final JsonWriterFactory wFactory = Json.createWriterFactory( null );
            final JsonWriter writer = wFactory.createWriter( out );

            writer.write( object );
            writer.close();

        } catch ( JsonException e ) {
            // I/O error
            throw e;
        } catch ( IllegalStateException e ) {
            throw new JsonException( e.toString() );
        }
    }
}
