package eu.fp7.secured.rule.action;

public enum IPSecActionType implements Action{
	AH, INVERT_AH, ESP, INVERT_ESP;
	
	@Override
	public Action actionClone() {
		return this;
	}
}
