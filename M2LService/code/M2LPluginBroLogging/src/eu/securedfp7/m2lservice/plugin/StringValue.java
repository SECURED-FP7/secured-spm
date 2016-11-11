package eu.securedfp7.m2lservice.plugin;

import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public class StringValue extends Value< String > {

    public StringValue( final String type,
                        final String value ) {
        super ( type, value );
    }

    public JsonObjectBuilder toJson( final JsonBuilderFactory factory ) {

        if ( !this.validate() ) {
            throw new JsonException( "Invalid Value" );
        }

        final JsonObjectBuilder builder = factory.createObjectBuilder();
        builder.add( "type", this.type );
        builder.add( "value", this.value );

        return builder;
    }

    public boolean validate() {
        return ( this.type != null
                 || this.value != null );
    }
}
