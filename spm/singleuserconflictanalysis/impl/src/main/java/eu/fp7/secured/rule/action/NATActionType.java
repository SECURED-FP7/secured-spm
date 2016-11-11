package eu.fp7.secured.rule.action;

public enum NATActionType implements Action{
	PRENAT, POSTNAT;
	
	@Override
	public String toString(){
		if(this == PRENAT)
			return "PRENAT";
		else if (this == POSTNAT)
			return "POSTNAT";
		return "";
	}
	
	@Override
	public Action actionClone() {
		return this;
	}
}
