package eu.fp7.secured.rule.action;


public enum ComparisonAction implements Action{
	EQUAL, DIFFERENT;

	@Override
	public Action actionClone() {
		return this;
	}
}
