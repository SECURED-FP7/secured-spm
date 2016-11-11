package eu.fp7.secured.exception.rule;

public class InvalidNetException extends Exception {

	static final long serialVersionUID = 15L;
	
	public InvalidNetException(){}

	public InvalidNetException(String msg)
	{
		super(msg);
	}
}

