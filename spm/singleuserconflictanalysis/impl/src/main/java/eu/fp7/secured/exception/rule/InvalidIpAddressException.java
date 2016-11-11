package eu.fp7.secured.exception.rule;

public class InvalidIpAddressException extends Exception {

	static final long serialVersionUID = 14L;
	
	public InvalidIpAddressException(){}

	public InvalidIpAddressException(String msg)
	{
		super(msg);
	}
	
}
