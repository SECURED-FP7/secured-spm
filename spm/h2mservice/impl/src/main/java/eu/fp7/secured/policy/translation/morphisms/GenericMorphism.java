package eu.fp7.secured.policy.translation.morphisms;

import java.util.List;

import eu.fp7.secured.rule.impl.GenericRule;


public interface GenericMorphism {
	public List<GenericRule> exportRules() throws Exception;
}
