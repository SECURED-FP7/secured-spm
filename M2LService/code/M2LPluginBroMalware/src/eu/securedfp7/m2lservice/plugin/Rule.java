package eu.securedfp7.m2lservice.plugin;

import java.util.List;
import java.util.LinkedList;

import javax.json.JsonObjectBuilder;
import javax.json.JsonArrayBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;

public class Rule {

    public enum Event {
        INVALID,
        CONNECTION,
        FILE
    }

    public enum Action {
        INVALID,
        LOG,
        MALWARE_DETECTION
    }

    private String id = null;
    private HSPLInfo hspl = null;
    private String operation = null;
    private Event event = Event.INVALID;
    private Action action = Action.INVALID;
    private List< Value > parameters = new LinkedList< Value >();
    private List< Value > conditions = new LinkedList< Value >();

    public Rule() {
    }

    public String getId() {
        return this.id;
    }

    public void setId( final String id ) {
        this.id = id;
    }

    public HSPLInfo getHSPL() {
        return this.hspl;
    }

    public void setHSPL( final HSPLInfo hspl ) {
        this.hspl = hspl;
    }

    public String getOperation() {
        return this.operation;
    }

    public void setOperation( final String op ) {
        this.operation = op;
    }

    public Event getEvent() {
        return this.event;
    }

    public void setEvent( final Event ev ) {
        this.event = ev;
    }

    public Action getAction() {
        return this.action;
    }

    public void setAction( final Action a ) {
        this.action = a;
    }

    public void addParameter( final Value v ) {
        this.parameters.add( v );
    }

    public void addCondition( final Value v ) {
        this.conditions.add( v );
    }

    // TODO: this is ugly:
    private String eventToString( final Event ev ) {

        switch ( ev ) {
        case INVALID:    return null;
        case CONNECTION: return "EVENT_CONNECTION";
        case FILE:       return "EVENT_FILE";
        default:         return null;
        }
    }

    // TODO: this is ugly:
    private String actionToString( final Action ac ) {

        switch( ac ) {
        case INVALID:           return null;
        case LOG:               return "log";
        case MALWARE_DETECTION: return "log"; // Currently we only support logging
        default:                return null;
        }
    }

    public JsonObjectBuilder toJson( final JsonBuilderFactory factory ) {

        if ( !this.validate() ) {
            throw new JsonException( "Invalid Rule" );
        }

        final JsonObjectBuilder builder = factory.createObjectBuilder();
        builder.add( "id", this.id );
        builder.add( "hspl", this.hspl.toJson( factory ) );
        builder.add( "operation", this.operation );
        builder.add( "event", this.eventToString( this.event ) );
        builder.add( "action", this.actionToString( this.action ) );

        final JsonArrayBuilder parmBuilder = factory.createArrayBuilder();
        for ( Value item : this.parameters ) {
            parmBuilder.add( item.toJson( factory ) );
        }

        builder.add( "parameters", parmBuilder );

        final JsonArrayBuilder condBuilder = factory.createArrayBuilder();
        for ( Value item : this.conditions ) {
            condBuilder.add( item.toJson( factory ) );
        }

        builder.add( "conditions", condBuilder );

        return builder;
    }

    public boolean validate() {

        if ( this.id == null ) {
            return false;
        }

        if ( this.hspl == null || !this.hspl.validate() ) {
            return false;
        }

        if ( this.operation == null ) {
            return false;
        }

        if ( this.event == Event.INVALID ) {
            return false;
        }

        if ( this.action == Action.INVALID ) {
            return false;
        }

        for ( final Value item : this.parameters ) {
            if ( !item.validate() ) {
                return false;
            }
        }

        for ( final Value item : this.conditions ) {
            if ( !item.validate() ) {
                return false;
            }
        }

        return true;
    }
}
