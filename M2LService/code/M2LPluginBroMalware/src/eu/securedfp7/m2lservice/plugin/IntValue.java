package eu.securedfp7.m2lservice.plugin;

import java.lang.Integer;

import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public class IntValue extends Value< Integer > {

    public IntValue( final String type,
                     final int value ) {
        super( type, new Integer( value ) );
    }

    public JsonObjectBuilder toJson( final JsonBuilderFactory factory ) {

        if ( !this.validate() ) {
            throw new JsonException( "Invalid Value" );
        }

        final JsonObjectBuilder builder = factory.createObjectBuilder();
        builder.add( "type", this.type );
        builder.add( "value", this.value.intValue() );

        return builder;
    }

    public boolean validate() {
        return ( this.type != null
                 || this.value != null );
    }
}
