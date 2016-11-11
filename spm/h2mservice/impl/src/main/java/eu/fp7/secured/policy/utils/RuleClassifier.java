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

public class RuleClassifier {
	
	private final Logger LOGGER = Logger.getLogger(RuleClassifier.class.getName());

	private HashMap<String, BlockList> classifierMap;
	private BlockList[] block_list;
	private LinkedList<GenericRule> rule_list;
	private Policy policy;
	

	public RuleClassifier(Policy policy) {
		classifierMap = new HashMap<String, BlockList>();
		rule_list = new LinkedList<GenericRule>();
		rule_list.add(null);
		this.policy = policy;
	}

	public void addRule(GenericRule rule) throws UnsupportedSelectorException {
		rule_list.add(rule);
		for (String s : classifierMap.keySet()) {
			BlockList list = classifierMap.get(s);
			list.insert(rule.getConditionClause().get(s), rule_list.size() - 1);
		}
	}

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

	public HashMap<String, BlockList> getClassifierMap() {
		return classifierMap;
	}

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

	
	
	public boolean isHidden(GenericRule rule, GenericRule[] hinders) throws NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException {
		BitSet bitSet = new BitSet();

		for (GenericRule r : hinders) {
			if(policy.getResolutionStrategy().compare(r, rule)==ResolutionComparison.UNIVERSALLY_LESS)
				bitSet.set(rule_list.indexOf(r));
		}
		
		return recursive_hinder_verification(0, bitSet, rule);
	}

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

	
	public boolean isUnnecessary(GenericRule rule, GenericRule[] rules){
		BitSet bitSet = new BitSet();

		for (GenericRule r : rules) {
			bitSet.set(rule_list.indexOf(r));
		}
		
		return recursive_unnecessary_verification(0, bitSet, rule);
	}
	
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
	
	private Collection<GenericRule> getRulesByBS(BitSet bs) {
		Set<GenericRule> set = new HashSet<GenericRule>();
		for (int i = bs.nextSetBit(0); i >= 0; i = bs.nextSetBit(i + 1)) {
			set.add(rule_list.get(i));
		}
		return set;
	}
}
