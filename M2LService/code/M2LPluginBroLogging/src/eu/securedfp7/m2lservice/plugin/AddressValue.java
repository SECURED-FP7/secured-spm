package eu.securedfp7.m2lservice.plugin;

import java.net.URI;
import java.net.URISyntaxException;

import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public class AddressValue extends Value< URI > {

    public AddressValue( final String type,
                         final String host,
                         final int port ) throws URISyntaxException {
        super( type,
               new URI( null, null, host, port, null, null, null ) );
    }

    public AddressValue( final String type,
                         final String host ) throws URISyntaxException {
        super( type,
               new URI( null, null, host, -1, null, null, null ) );
    }

    public AddressValue( final String type,
                         final int port ) throws URISyntaxException {
        super( type,
               new URI( null, null, null, port, null, null, null ) );
    }

    public JsonObjectBuilder toJson( final JsonBuilderFactory factory ) {

        if ( !this.validate() ) {
            throw new JsonException( "Invalid Value" );
        }

        final JsonObjectBuilder builder = factory.createObjectBuilder();
        builder.add( "type", this.type );

        final JsonObjectBuilder valBuilder = factory.createObjectBuilder();
        final String host = this.value.getHost();
        if ( host != null ) {
            valBuilder.add( "address", host );
        }

        final int port = this.value.getPort();
        if ( port >= 0 ) {
            valBuilder.add( "port", port );
        }

        builder.add( "value", valBuilder );

        return builder;
    }

    public boolean validate() {
        return ( this.type != null
                 || this.value != null
                 || ( this.value.getHost() == null
                      && this.value.getPort() == -1 ) );
    }
}
