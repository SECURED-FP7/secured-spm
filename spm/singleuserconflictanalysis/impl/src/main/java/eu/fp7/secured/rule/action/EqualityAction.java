package eu.fp7.secured.rule.action;

public enum EqualityAction implements Action{
	EQUAL, DIFFERENT;
	
	public String toString(){
		if(this == EQUAL)
			return "EQUAL";
		else
			return "DIFFERENT";
	}

	
	@Override
	public Action actionClone() {
		return this;
	}
}
