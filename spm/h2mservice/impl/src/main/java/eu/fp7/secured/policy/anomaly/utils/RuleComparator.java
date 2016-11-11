package eu.fp7.secured.policy.anomaly.utils;

import java.util.Comparator;

import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.impl.GenericRule;


public class RuleComparator implements Comparator<GenericRule>{
	private GenericConflictResolutionStrategy resolver;
	
	public RuleComparator(Policy policy) {
		this.resolver = policy.getResolutionStrategy();
	}
	
	@Override
	public int compare(GenericRule r1, GenericRule r2) {
		ResolutionComparison comp = null;
		try {
			comp = resolver.compare(r1, r2);
		} catch (NoExternalDataException e) {
			e.printStackTrace();
		} catch (DuplicatedRuleException e) {
			e.printStackTrace();
		} catch (UnmanagedRuleException e) {
			e.printStackTrace();
		}
		if( comp == ResolutionComparison.UNIVERSALLY_LESS) return 1;
		else if(comp == ResolutionComparison.UNIVERSALLY_GREATER) return -1;
		else return 0;
	}
}