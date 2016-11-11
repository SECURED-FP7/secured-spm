package eu.securedfp7.m2lservice.plugin;

import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public class HSPLInfo {

    private String id;
    private String text;

    public HSPLInfo( final String id,
                     final String text ) {
        this.id = id;
        this.text = text;
    }

    public String getId() {
        return this.id;
    }

    public String getText() {
        return this.text;
    }

    public JsonObjectBuilder toJson( final JsonBuilderFactory factory ) {

        if ( !this.validate() ) {
            throw new JsonException( "Invalid Rule" );
        }

        final JsonObjectBuilder builder = factory.createObjectBuilder();
        builder.add( "id", this.id );
        builder.add( "text", this.text );

        return builder;
    }

    public boolean validate() {

        if ( this.id == null ) {
            return false;
        }

        if ( this.text == null ) {
            return false;
        }

        return true;
    }

}
