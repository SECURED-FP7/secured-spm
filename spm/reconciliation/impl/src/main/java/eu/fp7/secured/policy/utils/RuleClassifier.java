/*******************************************************************************
 * Copyright (c) 2015 Politecnico di Torino.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     TorSec - SECURED Team - initial API and implementation
 ******************************************************************************/
package eu.fp7.secured.policy.utils;

import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class RuleClassifier.
 */
public class RuleClassifier {
	
	/** The logger. */
	private final Logger LOGGER = Logger.getLogger(RuleClassifier.class.getName());

	/** The classifier map. */
	private HashMap<String, BlockList> classifierMap;
	
	/** The block_list. */
	private BlockList[] block_list;
	
	/** The rule_list. */
	private LinkedList<GenericRule> rule_list;
	
	/** The policy. */
	private Policy policy;
	

	/**
	 * Instantiates a new rule classifier.
	 *
	 * @param policy the policy
	 */
	public RuleClassifier(Policy policy) {
		classifierMap = new HashMap<String, BlockList>();
		rule_list = new LinkedList<GenericRule>();
		rule_list.add(null);
		this.policy = policy;
	}

	/**
	 * Adds the rule.
	 *
	 * @param rule the rule
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	public void addRule(GenericRule rule) throws UnsupportedSelectorException {
		rule_list.add(rule);
		for (String s : classifierMap.keySet()) {
			BlockList list = classifierMap.get(s);
			list.insert(rule.getConditionClause().get(s), rule_list.size() - 1);
		}
	}

	/**
	 * Adds the selector.
	 *
	 * @param name the name
	 * @param blockList the block list
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 */
	public void addSelector(String name, BlockList blockList) throws UnsupportedSelectorException {
		classifierMap.put(name, blockList);
		for (int i = 1; i < rule_list.size(); i++) {
			blockList.insert(null, i);
		}
		
		block_list = new BlockList[classifierMap.values().size()];
		int i = 0;
		for (BlockList pl : classifierMap.values()) {
			block_list[i++] = pl;
		}
	}

	/**
	 * Gets the classifier map.
	 *
	 * @return the classifier map
	 */
	public HashMap<String, BlockList> getClassifierMap() {
		return classifierMap;
	}

	/**
	 * Gets the intersecting rules.
	 *
	 * @param rule the rule
	 * @return the intersecting rules
	 */
	public LinkedList<GenericRule> getIntersectingRules(GenericRule rule) {
		if (!rule_list.contains(rule))
			return null;

		LinkedList<GenericRule> return_list = new LinkedList<GenericRule>();

		BitSet bitSet = new BitSet();

		bitSet.set(1, rule_list.size());

		for (String sn : rule.getConditionClause().getSelectorsNames()) {
			bitSet.and(classifierMap.get(sn).getBitSet(rule_list.indexOf(rule)));
		}

		for (int i = bitSet.nextSetBit(0); i >= 0; i = bitSet.nextSetBit(i + 1)) {
			return_list.add(rule_list.get(i));
		}

		return return_list;
	}

	
	
	/**
	 * Checks if is hidden.
	 *
	 * @param rule the rule
	 * @param hinders the hinders
	 * @return true, if is hidden
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicatedRuleException the duplicated rule exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	public boolean isHidden(GenericRule rule, GenericRule[] hinders) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		BitSet bitSet = new BitSet();

		for (GenericRule r : hinders) {
			if(policy.getResolutionStrategy().compare(r, rule)==ResolutionComparison.UNIVERSALLY_LESS)
				bitSet.set(rule_list.indexOf(r));
		}
		
		return recursive_hinder_verification(0, bitSet, rule);
	}

	/**
	 * Recursive_hinder_verification.
	 *
	 * @param n the n
	 * @param base the base
	 * @param rule the rule
	 * @return true, if successful
	 */
	private boolean recursive_hinder_verification(int n, BitSet base, GenericRule rule) {
		try {
			for (Block p : (List<Block>) block_list[n].getBlocks()) {
				if(p.getBs().get(rule_list.indexOf(rule))){
					if (!base.intersects(p.getBs()))
						return false; // verificare la default action
					else {
						BitSet bs_new = ((BitSet) base.clone());
						bs_new.and(p.getBs());
						if ((n+1) < block_list.length && !recursive_hinder_verification(n + 1, bs_new, rule)) {
							return false;
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return true;

	}

	
	/**
	 * Checks if is unnecessary.
	 *
	 * @param rule the rule
	 * @param rules the rules
	 * @return true, if is unnecessary
	 */
	public boolean isUnnecessary(GenericRule rule, GenericRule[] rules){
		BitSet bitSet = new BitSet();

		for (GenericRule r : rules) {
			bitSet.set(rule_list.indexOf(r));
		}
		
		return recursive_unnecessary_verification(0, bitSet, rule);
	}
	
	/**
	 * Recursive_unnecessary_verification.
	 *
	 * @param n the n
	 * @param base the base
	 * @param rule the rule
	 * @return true, if successful
	 */
	private boolean recursive_unnecessary_verification(int n, BitSet base, GenericRule rule) {
		try {
			for (Block p : (List<Block>) block_list[n].getBlocks()) {
				if(p.getBs().get(rule_list.indexOf(rule))){
					if (!base.intersects(p.getBs())){
						if (!this.policy.getDefaultAction().equals(rule.getAction())) 
							return false;
					} else {
						BitSet bs_new = ((BitSet) base.clone());
						bs_new.and(p.getBs());
						if ((n+1) < block_list.length && !recursive_unnecessary_verification(n + 1, bs_new, rule)) {
							return false;
						} else {
							Collection<GenericRule> remaining_rules = getRulesByBS(bs_new);
							if (policy.getResolutionStrategy().composeActions(remaining_rules) != policy.getResolutionStrategy().composeActions(remaining_rules, rule)) 
								return false;
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return true;

	}
	
	/**
	 * Gets the rules by bs.
	 *
	 * @param bs the bs
	 * @return the rules by bs
	 */
	private Collection<GenericRule> getRulesByBS(BitSet bs) {
		Set<GenericRule> set = new HashSet<GenericRule>();
		for (int i = bs.nextSetBit(0); i >= 0; i = bs.nextSetBit(i + 1)) {
			set.add(rule_list.get(i));
		}
		return set;
	}
}
