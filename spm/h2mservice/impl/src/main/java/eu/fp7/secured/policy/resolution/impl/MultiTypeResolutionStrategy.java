package eu.fp7.secured.policy.resolution.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;


public class MultiTypeResolutionStrategy extends GenericConflictResolutionStrategy {

	private static final String label = "MultiTypeResolutionStrategy";
	private static final String label_simple = "MTRS";
	
	private LinkedList<Policy> policy_list;
	
	private Action defaultAction;

	public MultiTypeResolutionStrategy(LinkedList<Policy> policy_list, Action defaultAction) {
		this.policy_list = policy_list;
		this.defaultAction = defaultAction;
	}
	
	@Override
	public Action composeActions(GenericRule r1, GenericRule r2) throws NoExternalDataException, IncompatibleExternalDataException, InvalidActionException {
		GenericRule[] rules=new GenericRule[2];
		rules[1]=r1;
		rules[2]=r2;
		return composeActions(rules);
	}
	
	@Override
	public Action composeActions(GenericRule[] rules) throws NoExternalDataException, InvalidActionException{
		if(rules.length == 0)
			return defaultAction;
		
		HashMap<Policy, HashSet<GenericRule>> rp = new HashMap<Policy, HashSet<GenericRule>>();
		


		for(Policy p:policy_list){
			HashSet<GenericRule> hs = new HashSet<GenericRule>();
			rp.put(p, hs);
		}
		
		boolean found=false;
		for(GenericRule r: rules){
			found=false;
			for(Policy p:policy_list){
				HashSet<GenericRule> rs=rp.get(p);
				if(p.containsRule(r)){
					rs.add(r);
					found=true;
				}
			}
			if(!found){
				System.out.println("E:"+r.getName()+" : "+r.hashCode());
				throw new NoExternalDataException();
			}
		}
		
		for(Policy p:policy_list){
			if(!rp.get(p).isEmpty()){
//				System.out.println();
//				System.out.println(p.getName());
//				System.out.println(rp.get(p));
//				System.out.println(p.getResolutionStrategy().composeActions(rp.get(p)));
//				System.out.println();
				return p.getResolutionStrategy().composeActions(rp.get(p));
			}
		}

		return defaultAction;
		
	
	}

	
	
	@Override
	public ResolutionComparison compare(GenericRule r1, GenericRule r2) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		
		for(Policy p:policy_list){
			
			if(p.containsRule(r1) && p.containsRule(r2))
				return p.getResolutionStrategy().compare(r1, r2);
		}
		
		return ResolutionComparison.DIFFERENT_SET;

	}

	
	@Override
	public boolean isActionEquivalent(GenericRule r1, GenericRule r2) {
		return r1.getAction().equals(r2.getAction());
	}

	
	@Override
	public GenericConflictResolutionStrategy cloneResolutionStrategy() {
		MultiTypeResolutionStrategy res = new MultiTypeResolutionStrategy(policy_list, defaultAction);
		
		return res;
	}
	
	
	@Override
	public String toString(){
		return label;
	}
	
	@Override
	public String toSimpleString() {
		return label_simple;
	}
}
