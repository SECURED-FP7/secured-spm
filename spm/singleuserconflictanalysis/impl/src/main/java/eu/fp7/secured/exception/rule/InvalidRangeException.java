package eu.fp7.secured.exception.rule;

public class InvalidRangeException extends Exception {

	static final long serialVersionUID = 17L;
	
	public InvalidRangeException(){}

	public InvalidRangeException(String msg)
	{
		super(msg);
	}
}
