package eu.fp7.secured.rule.action;

import eu.fp7.secured.rule.impl.ConditionClause;

public class NATAction extends TransformatonAction{
	
	private NATActionType NATAction;

	public NATAction(NATActionType NATAction, ConditionClause transformation) {
		super(transformation);
		this.NATAction = NATAction;
	}

	public NATActionType getNATAction() {
		return NATAction;
	}
	
	@Override
	public Action actionClone() {
		return new NATAction(NATAction, getTransformation().conditionClauseClone());
	}
}
