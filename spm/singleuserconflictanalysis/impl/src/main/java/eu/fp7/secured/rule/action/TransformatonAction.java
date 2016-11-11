package eu.fp7.secured.rule.action;

import eu.fp7.secured.rule.impl.ConditionClause;

public abstract class TransformatonAction implements Action  {
	
	private ConditionClause transformation;
	
	public TransformatonAction(ConditionClause transformation){
		this.transformation=transformation;
	}
	
	public ConditionClause getTransformation(){
		return transformation;
	}

	
}
