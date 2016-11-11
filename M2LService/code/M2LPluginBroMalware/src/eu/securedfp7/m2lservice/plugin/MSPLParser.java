package eu.securedfp7.m2lservice.plugin;

import java.lang.Integer;
import java.lang.NumberFormatException;

import java.util.List;
import java.util.LinkedList;
import java.util.regex.PatternSyntaxException;

import java.io.InputStream;

import java.net.URL;
import java.net.URISyntaxException;

import java.math.BigInteger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import main.java.mspl_class.ITResource;
import main.java.mspl_class.Configuration;
import main.java.mspl_class.MaliciousFileAnalysisCapability;
import main.java.mspl_class.LoggingCapability;
import main.java.mspl_class.Capability;
import main.java.mspl_class.AntiMalwareAction;
import main.java.mspl_class.LoggingAction;
import main.java.mspl_class.ConfigurationAction;
import main.java.mspl_class.FileSystemCondition;
import main.java.mspl_class.ApplicationLayerCondition;
import main.java.mspl_class.AntiMalwareCondition;
import main.java.mspl_class.EventCondition;
import main.java.mspl_class.PacketFilterCondition;
import main.java.mspl_class.LoggingCondition;
import main.java.mspl_class.ConfigurationCondition;
import main.java.mspl_class.HSPL;
import main.java.mspl_class.ConfigurationRule;
import main.java.mspl_class.ExternalData;
import main.java.mspl_class.LSTP;
import main.java.mspl_class.FMR;
import main.java.mspl_class.ATP;
import main.java.mspl_class.ALL;
import main.java.mspl_class.MSTP;
import main.java.mspl_class.DTP;
import main.java.mspl_class.ResolutionStrategy;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.LevelType;
import main.java.mspl_class.HTTPCondition;

public class MSPLParser {

    private Rule.Action defaultAction = Rule.Action.INVALID;
    private List< Rule > rules = new LinkedList< Rule >();

    public void parse( final InputStream mspl,
                       final List< Rule > to ) throws BadConfigException {
        try {
            final JAXBContext ctx = JAXBContext.newInstance( ITResource.class );
            final Unmarshaller um = ctx.createUnmarshaller();
            final ITResource root = (ITResource)um.unmarshal( mspl );

            this.visit( root );

            if ( this.rules.isEmpty() ) {
                throw new BadConfigException( "No rules found" );
            }

            to.addAll( this.rules );

            return;

        } catch ( final JAXBException e) {
            throw new BadConfigException( e.getMessage() );

        } finally {
            this.rules.clear();
            this.defaultAction = Rule.Action.INVALID;
        }
    }

    // Implements the visitor pattern

    private void visit( final ITResource in ) throws BadConfigException {
        final String id = in.getID();

        this.visit( in.getConfiguration() );
    }

    private void visit( final Configuration in ) throws BadConfigException {

        // Handle in subclasses:
        // final List< Capability > capabilities = in.getCapability();

        if ( in instanceof RuleSetConfiguration ) {
            this.visit( (RuleSetConfiguration)in );
        } else {
            throw new BadConfigException( "Unexpected Configuration type" );
        }
    }

    private void visit( final RuleSetConfiguration in ) throws BadConfigException {
        final String name = in.getName();

        final List< Capability > capabilities = in.getCapability();
        for ( final Capability capability : capabilities ) {
            this.visit( capability );
        }

        // Might be null
        final ConfigurationAction action = in.getDefaultAction();
        if ( action != null ) {
            this.visit( action, null );
        }

        // NOTE: might be empty!
        final List< ConfigurationRule > rules = in.getConfigurationRule();
        if ( rules == null || rules.isEmpty() ) {
            throw new BadConfigException( "At least one rule must be"
                                          + " present" );
        }

        for ( final ConfigurationRule rule : rules ) {
            this.visit( rule );
        }

        this.visit( in.getResolutionStrategy() );
    }

    private void visit( final Capability in ) throws BadConfigException {
//        final String name = in.getName()
        if ( in instanceof MaliciousFileAnalysisCapability ) {
            this.visit( (MaliciousFileAnalysisCapability)in );
        } else if ( in instanceof LoggingCapability ) {
            this.visit( (LoggingCapability)in );
        } else if ( in instanceof Capability ) {
            // ?
        } else {
            throw new BadConfigException( "Unexpected Capability type" );
        }
    }

    private void visit( final MaliciousFileAnalysisCapability in ) throws BadConfigException {
//        final boolean online  = in.isSupportOnlineTraficAnalysis();
//        final boolean offline = in.isSupportOfflineTraficAnalysis();
//        final String fileType = in.getFileType();
    }

    private void visit( final LoggingCapability in ) throws BadConfigException {
//        final String resType = in.getResourceType();
    }

    private void visit( final ConfigurationAction in,
                        final Rule rule ) throws BadConfigException {
        if ( in instanceof AntiMalwareAction ) {
            this.visit( (AntiMalwareAction)in, rule );
        } else if ( in instanceof LoggingAction ) {
            this.visit( (LoggingAction)in, rule );
        } else {
            throw new BadConfigException( "Unexpected Action" );
        }
    }

    private void visit( final AntiMalwareAction in,
                        final Rule rule ) throws BadConfigException {
//        final String type = in.getAntiMalwareActionType();
        if ( rule == null ) {
            this.defaultAction = Rule.Action.MALWARE_DETECTION;
        } else {
            rule.setAction( Rule.Action.MALWARE_DETECTION );
        }
    }

    private void visit( final LoggingAction in,
                        final Rule rule ) throws BadConfigException {
//       final String type = in.getLoggingActionType();
        if ( rule == null ) {
            this.defaultAction = Rule.Action.LOG;
        } else {
            rule.setAction( Rule.Action.LOG );
        }
    }

    private void visit( final ConfigurationRule in ) throws BadConfigException {
        final String name = in.getName();
        final boolean cnf = in.isIsCNF();

        final Rule rule = new Rule();
        rule.setId( name );

        // Action is either specified in the rule or the default action:

        final ConfigurationAction ca = in.getConfigurationRuleAction();
        if ( ca != null ) {
            this.visit( ca, rule );
        }

        if ( rule.getAction() == Rule.Action.INVALID ) {
            if ( this.defaultAction == Rule.Action.INVALID ) {
                throw new BadConfigException( "Undefined Action" );
            }
            rule.setAction( this.defaultAction );
        }

        this.visit( in.getConfigurationCondition(), rule );

        // Might be null
        final ExternalData data = in.getExternalData();
        if ( data != null ) {
            this.visit( data, rule );
        }

        // Might be empty!
        List< HSPL > hspls = in.getHSPL();
        for ( final HSPL hspl : hspls ) {
            this.visit( hspl, rule );
        }

        if ( !rule.validate() ) {
            throw new BadConfigException( "Invalid Rule: " + name );
        }

        this.rules.add( rule );
    }

    private void visit( final ConfigurationCondition in,
                        final Rule rule ) throws BadConfigException {
        // Handled in subclasses:
        // final boolean cnf = in.isIsCNF();

        if ( in instanceof AntiMalwareCondition ) {
            this.visit( (AntiMalwareCondition)in, rule );

            rule.setOperation( "detect-MHR" );
            rule.setEvent( Rule.Event.FILE );

        } else if ( in instanceof LoggingCondition ) {
            this.visit( (LoggingCondition)in, rule );

            rule.setOperation( "count" );
        } else {
            throw new BadConfigException( "Unexpected Condition type" );
        }
    }

    private void visit( final AntiMalwareCondition in,
                        final Rule rule ) throws BadConfigException {
        final boolean cnf = in.isIsCNF();

        final FileSystemCondition fsc = in.getFileSystemCondition();
        if ( fsc != null ) {
            throw new BadConfigException( "FileSystemCondition is not"
                                          + " defined with"
                                          + " AntiMalwareCondition" );
        }

        final ApplicationLayerCondition ac = in.getApplicationLayerCondition();
        if ( ac == null ) {
            throw new BadConfigException( "ApplicationLayerCondition must be "
                                          + "present in AntiMalwareCondition" );
        }

        this.visit( ac, rule );

        final EventCondition event = in.getEventCondition();
        if ( event != null ) {
            throw new BadConfigException( "EventCondition is not"
                                          + " defined with"
                                          + " AntiMalwareCondition" );
        }
    }

    private void visit( final FileSystemCondition in,
                        final Rule rule ) throws BadConfigException {
//       final String file = in.getFilename(); // Might be null
//       final String path = in.getPath();     // Might be null

        // Might be null
        final PacketFilterCondition pf = in.getPacketFilterCondition();
        if ( pf != null ) {
            this.visit( in.getPacketFilterCondition(), rule );
        }
    }

    private List< String > parseAddressList( final String string )  throws BadConfigException {

        final List< String > list = new LinkedList< String >();
        if ( string == null ) {
            return list;
        }

        final String[] parts;
        try {
            parts = string.split( "," );
        } catch ( final PatternSyntaxException e ) {
            throw new BadConfigException( "Internal error" );
        }

        // TODO: currently expects valid IP / hostname

        for ( final String part : parts ) {
            list.add( part.trim() ); // AddressValue constructor does syntax checking!
        }

        return list;
    }

    private List< Integer > parsePortList( final String string )  throws BadConfigException {

        final List< Integer > list = new LinkedList< Integer >();
        if ( string == null ) {
            return list;
        }

        final String[] parts;
        try {
            parts = string.split( "," );
        } catch ( final PatternSyntaxException e ) {
            throw new BadConfigException( "Internal error" );
        }

        for ( final String part : parts ) {
            try {
                list.add( Integer.valueOf( part.trim() ) );
            } catch ( final NumberFormatException e ) {
                throw new BadConfigException( "Invalid port" );
            }
        }

        return list;
    }

    private void visit( final PacketFilterCondition in,
                        final Rule rule ) throws BadConfigException {
        final String src       = in.getSourceAddress();     // Might be null
        final String dst       = in.getDestinationAddress();// Might be null
        final String srcPort   = in.getSourcePort();        // Might be null
        final String dstPort   = in.getDestinationPort();   // Might be null
// TODO:
//        final String direction = in.getDirection();         // Might be null
//        final String iFace     = in.getInterface();         // Might be null
//        final String protocol  = in.getProtocolType();      // Might be null

        final List< String > srcs = this.parseAddressList( src );
        final List< String > dsts = this.parseAddressList( dst );
        final List< Integer > sPorts = this.parsePortList( srcPort );
        final List< Integer > dPorts = this.parsePortList( dstPort );

        if ( srcs.isEmpty() ) {
            for ( final Integer port : sPorts ) {
                try {
                    rule.addCondition( new AddressValue( "source_port", port.intValue() ) );
                } catch ( final URISyntaxException e ) {
                    throw new BadConfigException( e.getMessage() );
                }
            }
        } else {
            if ( sPorts.isEmpty() ) {
                for ( final String host : srcs ) {
                    try {
                        rule.addCondition( new AddressValue( "source", host ) );
                    } catch ( final URISyntaxException e ) {
                        throw new BadConfigException( e.getMessage() );
                    }
                }
            } else {
                for ( final Integer port : sPorts ) {
                    final int p = port.intValue();
                    for ( final String host : srcs ) {
                        try{
                            rule.addCondition( new AddressValue( "source", host, p ) );
                        } catch ( final URISyntaxException e ) {
                            throw new BadConfigException( e.getMessage() );
                        }
                    }
                }
            }
        }

        if ( dsts.isEmpty() ) {
            for ( final Integer port : dPorts ) {
                try {
                    rule.addCondition( new AddressValue( "destination_port", port.intValue() ) );
                } catch ( final URISyntaxException e ) {
                    throw new BadConfigException( e.getMessage() );
                }
            }
        } else {
            if ( dPorts.isEmpty() ) {
                for ( final String host : dsts ) {
                    try {
                        rule.addCondition( new AddressValue( "destination", host ) );
                    } catch ( final URISyntaxException e ) {
                        throw new BadConfigException( e.getMessage() );
                    }
                }
            } else {
                for ( final String host : dsts ) {
                    for ( final Integer port : dPorts ) {
                        try {
                            rule.addCondition( new AddressValue( "destination", host, port.intValue() ) );
                        } catch ( final URISyntaxException e ) {
                            throw new BadConfigException( e.getMessage() );
                        }
                    }
                }
            }
        }

        // Might be empty!
        final List< String > states = in.getState();
        for ( final String state : states ) {
            // TODO: check valid states!
            rule.addCondition( new StringValue( "state", state ) );
        }
    }

    private void visit( final ApplicationLayerCondition in,
                        final Rule rule ) throws BadConfigException {
        final String url         = in.getURL();           // Might be null
        final HTTPCondition http = in.getHttpCondition(); // Might be null
        final String extension   = in.getFileExtension(); // Might be null
        final String mime        = in.getMimeType();      // Might be null
        final Integer maxConn    = in.getMaxconn();       // Might be null
        final String dstDomain   = in.getDstDomain();     // Might be null
        final String srcDomain   = in.getSrcDomain();     // Might be null
        final String urlRegEx    = in.getURLRegex();      // Might be null

        if ( http != null
             || extension != null
             || maxConn != null
             || dstDomain != null
             || srcDomain != null
             || urlRegEx != null
             // expect exactly one condition:
             || ( mime != null && url != null ) ) {
            throw new BadConfigException( "Unexpected ApplicationLayerCondition" );
        }

        if ( mime != null ) {
            String value = mime.trim();
            if ( value.endsWith( "," ) ) {
                value = value.substring( 0, value.length() - 1 );
            }

            rule.addCondition( new StringValue( "mime-type", value ) );

            return;
        }

        if ( url != null ) {
            // Let's assume its a string consisting of comma-separated names
            List< String > hosts = parseAddressList( url.trim() );

            for ( final String host : hosts ) {
                try {
                    // TODO: let's assume all the names represent destinations,
                    //       since there is really no way to say what it is.
                    rule.addCondition( new AddressValue( "destination", host ) );
                } catch ( final URISyntaxException e ) {
                    throw new BadConfigException( e.getMessage() );
                }
            }

            return;
        }

        throw new BadConfigException( "Invalid ApplicationLayerCondition" );
    }

    private void visit( final EventCondition in,
                        final Rule rule ) throws BadConfigException {

        final String event = in.getEvents();
        if ( event == null ) {
            throw new BadConfigException( "Exactly Event must be present"
                                          + " in EventCondition" );
        }

        if ( !event.equals( "EVENT_CONNECTION" ) ) {
            throw new BadConfigException( "Unexpected Event in"
                                          + " EventCondition" );
        }
        rule.setEvent( Rule.Event.CONNECTION );

        final BigInteger interval = in.getInterval();
        if ( interval != null ) {
            rule.addCondition( new IntValue( "interval",
                                             interval.intValue() ) );
        }

        final BigInteger threshold = in.getThreshold();
        if (threshold != null ) {
            rule.addCondition( new IntValue( "threshold",
                                             threshold.intValue() ) );
        }
    }

    private void visit( final LoggingCondition in,
                        final Rule rule ) throws BadConfigException {
        final boolean cnf = in.isIsCNF();

        final EventCondition event = in.getEventCondition();
        if ( event == null ) {
            throw new BadConfigException( "Exactly one EventCondition"
                                          + " must be present in LoggingCondition" );
        }

        this.visit( event, rule );

        final String object = in.getObject();
        if ( object != null ) {
            if ( !object.equals( "OBJ_CONNECTION" ) ) {
                throw new BadConfigException( "Unexpected Object" );
            }

            rule.addParameter( new StringValue( "object", object ) );

        } else {
            // Compensate missing value:
            rule.addParameter( new StringValue( "object", "OBJ_CONNECTION" ) );
        }

        // Might be empty!
        final List< PacketFilterCondition > pfs = in.getPacketCondition();
        for ( final PacketFilterCondition pf : pfs ) {
            this.visit( pf, rule );
        }

        final List< ApplicationLayerCondition > als = in.getApplicationCondition();
        for ( final ApplicationLayerCondition al : als ) {
            this.visit( al, rule );
        }

        // Require at least one condition:
        if ( ( pfs == null || pfs.isEmpty() )
             && ( als == null || als.isEmpty() ) ) {
            throw new BadConfigException( "One or more PacketFilterConditions"
                                          + " or ApplicationLayerConditions must"
                                          + " be present in LoggingCondition" );
        }
    }

    private void visit( final ExternalData in,
                        final Rule rule ) throws BadConfigException {
        //        ?
    }

    private void visit( final HSPL in,
                        final Rule rule ) throws BadConfigException {
        final String id   = in.getHSPLId();
        final String text = in.getHSPLText();

        rule.setHSPL( new HSPLInfo( id, text ) );
    }

    private void visit( final ResolutionStrategy in ) throws BadConfigException {

        if ( in instanceof LSTP ) {
            this.visit( (LSTP)in );
        } else if ( in instanceof FMR ) {
            this.visit( (FMR)in );
        } else if ( in instanceof ATP ) {
            this.visit( (ATP)in );
        } else if ( in instanceof ALL ) {
            this.visit( (ALL)in );
        } else if ( in instanceof MSTP ) {
            this.visit( (MSTP)in );
        } else if ( in instanceof DTP  ) {
            this.visit( (DTP)in );
        } else {
            throw new BadConfigException( "Unexpected ResolutionStrategy "
                                          + "type" );
        }
    }

    private void visit( final LSTP in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }

    private void visit( final FMR in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }

    private void visit( final ATP in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }

    private void visit( final ALL in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }

    private void visit( final MSTP in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }

    private void visit( final DTP in ) throws BadConfigException {

        // Might be empty!
        final List< ExternalData > datas = in.getExternalData();
        for ( final ExternalData data : datas ) {
            this.visit( data, null );
        }
    }
}
