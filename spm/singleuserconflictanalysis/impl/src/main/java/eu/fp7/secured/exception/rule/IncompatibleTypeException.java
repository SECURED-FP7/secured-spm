package eu.fp7.secured.exception.rule;

public class IncompatibleTypeException extends Exception{

	static final long serialVersionUID = 13L;
	
	public IncompatibleTypeException(){}

	public IncompatibleTypeException(String msg)
	{
		super(msg);
	}

}