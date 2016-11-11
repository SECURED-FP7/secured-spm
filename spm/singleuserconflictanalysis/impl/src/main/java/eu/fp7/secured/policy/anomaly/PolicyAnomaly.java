/*
 * 
 */
package eu.fp7.secured.policy.anomaly;

import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.rule.impl.GenericRule;



// TODO: Auto-generated Javadoc
/**
 * The class PolicyAnomaly is a container class for rules and thery conflict type,
 * it contains three member variables:
 * rule_set
 * conflict
 * policy_list.
 */
public class PolicyAnomaly {
	
	/** The private member variable rule_set contains the rules. */
	private GenericRule[] rule_set;
	
	/** The private member variable conflict contains the conflict type. */
	private ConflictType conflict;
	
	/** The private member variable policy_list contains the list of policies to which the rules apply. */
	private List<Policy> policy_list;
	
	
	/**
	 * Instantiates a new policy anomaly.
	 *
	 * @param policy_list the policy_list
	 * @param rule_set the rule_set
	 * @param conflict the conflict
	 */
	public PolicyAnomaly(List<Policy> policy_list, GenericRule[] rule_set, ConflictType conflict){
		this.rule_set = rule_set;
		this.conflict = conflict;
		this.policy_list = policy_list;
	}
	
	/**
	 * Instantiates a new policy anomaly.
	 *
	 * @param rule_set the rule_set
	 * @param conflict the conflict
	 */
	public PolicyAnomaly(GenericRule[] rule_set, ConflictType conflict){
		this.rule_set = rule_set;
		this.conflict = conflict;
		this.policy_list = null;
	}

	/**
	 * Gets the rule_set.
	 *
	 * @return the rule_set
	 */
	public GenericRule[] getRule_set() {
		return rule_set;
	}

	/**
	 * Gets the conflict.
	 *
	 * @return the conflict
	 */
	public ConflictType getConflict() {
		return conflict;
	}
	
	/**
	 * Gets the policy list.
	 *
	 * @return the policy list
	 */
	public List<Policy> getPolicyList(){
		return policy_list;
	}
	

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String ret="----------------------------\n";
		
		if(policy_list!=null){
			ret+="( ";
			for(Policy p:policy_list)
				ret+=p.getName()+" ";
			ret+=")\n ";		
		}
		for(GenericRule r:rule_set){
			ret+=r.getName()+" ";
		}

		ret+="\n"+conflict.toString()+"\n----------------------------";
		
		return ret;
	}
}
