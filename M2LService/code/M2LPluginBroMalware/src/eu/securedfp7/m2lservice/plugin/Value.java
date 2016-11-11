package eu.securedfp7.m2lservice.plugin;

import javax.json.JsonObjectBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public abstract class Value< T > {

    protected String type = null;
    protected T value     = null;

    protected Value( final String t, final T  v ) {
        this.type  = t;
        this.value = v;
    }

    public String getType() {
        return this.type;
    }

    public void setType( final String t ) {
        this.type = t;
    }

    public T getValue() {
        return this.value;
    }

    public void setValue( final T v ) {
        this.value = v;
    }

    public abstract JsonObjectBuilder toJson( final JsonBuilderFactory factory );

    public abstract boolean validate();
}
