package eu.fp7.secured.exception.rule;

public class OperationNotPossibleException extends Exception{

	static final long serialVersionUID = 19L;
	
	public OperationNotPossibleException(){}

	public OperationNotPossibleException(String msg)
	{
		super(msg);
	}

}