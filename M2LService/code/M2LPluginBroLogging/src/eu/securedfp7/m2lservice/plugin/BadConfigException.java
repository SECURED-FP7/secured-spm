package eu.securedfp7.m2lservice.plugin;

import java.lang.Exception;

public class BadConfigException extends Exception {

    public BadConfigException( String message ) {
        super( message );
    }
}
