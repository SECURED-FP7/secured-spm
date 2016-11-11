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
package eu.fp7.secured.policy.translation.canonicalform;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.ResolutionErrorException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.policy.anomaly.PolicyAnalyzer;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.BitSetManager;
import eu.fp7.secured.policy.utils.IndexingBitSet;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;



// TODO: Auto-generated Javadoc
/**
 * The Class CanonicalFormGenerator.
 */
public class CanonicalFormGenerator{
	
	
	/** The instance. */
	private static Hashtable<Policy, CanonicalFormGenerator> instance=new Hashtable<Policy, CanonicalFormGenerator>();
	
	/** The can. */
	private CanonicalForm can;

	/** The original clones. */
	private LinkedHashMap<GenericRule,GenericRule> originalClones;
	
	/** The necessary clones. */
	private LinkedHashMap<GenericRule,GenericRule> necessaryClones;
	
	/** The can rules. */
	private HashMap<Long,LinkedList<GenericRule>> canRules;

	//Associate a GenericRule to the labels representing the composing rules (bitmask)
	/** The can labels. */
	private HashMap<GenericRule,IndexingBitSet> canLabels;
	//Associate a label to a GenericRule
	/** The ibs label. */
	private HashMap<IndexingBitSet, GenericRule> ibsLabel;

	/** The originals label. */
	private HashMap<IndexingBitSet, GenericRule> originalsLabel;

	/** The can intersecting. */
	private LinkedList<GenericRule> canIntersecting;

	/** The bs manager. */
	private BitSetManager bsManager;
	
	/** The analyzer. */
	private PolicyAnalyzer analyzer;
	
	/** The policy. */
	private Policy policy;
	
	/**
	 * Gets the single instance of CanonicalFormGenerator.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 * @return single instance of CanonicalFormGenerator
	 */
	public static CanonicalFormGenerator getInstance(Policy policy, SelectorTypes selectorTypes){
		if (policy == null)
			throw new InvalidParameterException();
		
		if (policy instanceof CanonicalForm)
			throw new InvalidParameterException();
			
		if (instance.containsKey(policy))
			return instance.get(policy);
		
		CanonicalFormGenerator can_mng = new CanonicalFormGenerator(policy, selectorTypes);
		
		instance.put(policy, can_mng);
		
		return can_mng;
	}
	
	/**
	 * Instantiates a new canonical form generator.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 */
	private CanonicalFormGenerator(Policy policy, SelectorTypes selectorTypes){

		originalClones = new LinkedHashMap<GenericRule, GenericRule>();
		necessaryClones = new LinkedHashMap<GenericRule, GenericRule>();
		canRules = new HashMap<Long, LinkedList<GenericRule>>();
		canLabels = new HashMap<GenericRule, IndexingBitSet>();
		ibsLabel = new HashMap<IndexingBitSet, GenericRule>();
		originalsLabel = new HashMap<IndexingBitSet, GenericRule>();//Labels of the rules contained in the policy

		canIntersecting = new LinkedList<GenericRule>();;

		bsManager = new BitSetManager();

		analyzer = new PolicyAnalyzer(policy,selectorTypes);
		
		can = new CanonicalForm(policy, selectorTypes);
		
		this.policy = policy;
	}


	
	/**
	 * Generate closure.
	 *
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws ResolutionErrorException the resolution error exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	public void generateClosure() throws UnsupportedSelectorException, UnmanagedRuleException, ResolutionErrorException, NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException{
		
		
		Set<GenericRule> rulesToAdd = policy.getRuleSet();
		

		
		
		for (GenericRule r : rulesToAdd)
			originalClones.put(r, r.ruleClone());
		
		for (GenericRule r : rulesToAdd){
			originalClones.remove(r);
			//TODO: verifica se ancora necessario (JS: non capisco a cosa serva)
			necessaryClones.remove(r);
		}


		
		
		List<GenericRule> necessaryRules = analyzer.getNecessaryRules();

		

		
		/*
		 * Remove unnecessary rules that are in the set of rules to add
		 */
//		for (GenericRule r : rulesToAdd.toArray(new GenericRule[rulesToAdd.size()]))
//			if (!necessaryRules.contains(r))
//				rulesToAdd.remove(r);
		
		
		boolean canToRebuild=false;
		/* 
		 * If the previous set of necessary rules is not contained
		 * in the new one, then the insertion of new rules hides
		 * some of the previous necessary rules. So the
		 * canonical form must be rebuilt
		 */ 
		if (!necessaryRules.containsAll(necessaryClones.keySet()))
			canToRebuild=true;
		
		if (canToRebuild) {
			necessaryClones.clear();
			for (GenericRule r : necessaryRules)
				necessaryClones.put(r, originalClones.get(r));
			/*
			 * since we must rebuild the canonical form we clear the old
			 * data structure and the hashset rulesToAdd becomes the
			 * entire necessary rule set
			 */
			canLabels.clear();
			canRules.clear();
			ibsLabel.clear();
			originalClones.clear();
			
			bsManager = new BitSetManager();
			
			can.setSemiLattice(null);
			
			rulesToAdd.clear();
			rulesToAdd.addAll(necessaryRules);
		}
		
		
		

		for (GenericRule r : rulesToAdd)
			try {
				insertRule(can, r);
			} catch (SecurityException e) {
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (NoSuchMethodException e) {
				e.printStackTrace();
			} catch (InstantiationException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		
		can.setRules(canLabels.keySet());
		can.setLabels(canLabels);
		can.setIbsLabels(ibsLabel);
	}
	
	/**
	 * Decompose rule.
	 *
	 * @param r the r
	 * @param can the can
	 * @return the generic rule[]
	 */
	public GenericRule[] decomposeRule(GenericRule r, CanonicalForm can){
		IndexingBitSet ibs = canLabels.get(r);
		
		GenericRule [] rules = new GenericRule[ibs.cardinality()+1];
		
		IndexingBitSet index = new IndexingBitSet();
		
		int j=0;
		for (int i = ibs.nextSetBit(0); i >= 0; i = ibs.nextSetBit(i+1)) {
		    index.clear();
		    index.set(i);
		    rules[j++] = originalsLabel.get(index);
		 }
		
		return rules;
		
	}
	
	/**
	 * Insert rule.
	 *
	 * @param can the can
	 * @param ruleToInsert the rule to insert
	 * @throws NoExternalDataException the no external data exception
	 * @throws SecurityException the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws ClassNotFoundException the class not found exception
	 * @throws NoSuchMethodException the no such method exception
	 * @throws InstantiationException the instantiation exception
	 * @throws IllegalAccessException the illegal access exception
	 * @throws InvocationTargetException the invocation target exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws InvalidActionException the invalid action exception
	 */
	private void insertRule(CanonicalForm can, GenericRule ruleToInsert) throws NoExternalDataException, SecurityException, IllegalArgumentException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException, InvalidActionException{
		
		canIntersecting.clear();
		
		/*
		 * Setting the label for the ruleToInsert
		 * Each rule is assigned to a different bit in the bitmask
		 */
	
		GenericRule[] clone_rules = new GenericRule[1];
		clone_rules[0] = ruleToInsert;

		ConditionClause cc = ruleToInsert.getConditionClause().conditionClauseClone();
		LinkedList<HSPL> hspl = new LinkedList<>();
		hspl.addAll(ruleToInsert.getHSPLs());
		GenericRule ruleToInsertClone = new GenericRule(can.getResolutionStrategy().composeActions(clone_rules), cc, ruleToInsert.getName(), ruleToInsert.getMSPL_id(), hspl);
		

		
		canLabels.put(ruleToInsertClone, bsManager.getIndex());
		ibsLabel.put(canLabels.get(ruleToInsertClone), ruleToInsertClone);
		originalsLabel.put(canLabels.get(ruleToInsertClone), ruleToInsert);
		
	
		
		/*
		 * Now all the composition with the rule in R* are generated and inserted
		 * in the can.canConflicting list
		 * 
		 */
		 //For each hash value
		for(List<GenericRule> rl : canRules.values()){
			//For each (composite) rule
			for(GenericRule r : rl){
				
	
				
				if(r.isIntersecting(ruleToInsert)){//check if the intersection between the (composite) rule in canonical form and the current one is empty
					GenericRule [] rules = decomposeRule(r, can);
					rules[rules.length-1]=ruleToInsert;
					ConditionClause r_cc = r.getConditionClause().conditionClauseClone();
					r_cc.intersection(ruleToInsert.getConditionClause());
					
					List<HSPL> HSPLs = new LinkedList<>();
					HSPLs.addAll(r.getHSPLs());
					HSPLs.addAll(ruleToInsert.getHSPLs());
					HashSet<String> MSPLs = r.getMSPL_id();						
					MSPLs.addAll(ruleToInsert.getMSPL_id());
					
					GenericRule rComp = new GenericRule(can.getResolutionStrategy().composeActions(rules), r_cc, r.getName()+"_"+ruleToInsert.getName(), MSPLs, HSPLs);
					
					
					//Add the current rule
					
					

				
					canIntersecting.add(rComp);//is intersecting
					IndexingBitSet rCompLabel = (IndexingBitSet) canLabels.get(r).clone();
					rCompLabel.or(canLabels.get(ruleToInsertClone));//The new label is obtained as bit-wise or
					/*
					 * The label is set here, if the composition is not necessary in R*
					 * the labels will be removed in the following
					 */
					canLabels.put(rComp, rCompLabel);
					ibsLabel.put(rCompLabel, rComp);
					
				}
				
			}
		}
		
		/*
		 * the initial rule to be inserted
		 */
		canIntersecting.add(ruleToInsertClone);

		
		
		for (GenericRule r : canIntersecting){//For each rule that could be inserted in the canonical form
			
			long eqClass = r.getEquivalenceClass(can.getSelectorNames());
			
			
			LinkedList<GenericRule> eqClassList = canRules.get(eqClass);//Seek for an existing list attached to this value
	
			if (eqClassList==null){
				eqClassList = new LinkedList<GenericRule>();
				eqClassList.add(r);
				canRules.put(eqClass, eqClassList);

			} else {
				boolean found=false;
				
				
				GenericRule rEq=null;
				for (int i=0;i<eqClassList.size() && !found;i++){
					rEq = eqClassList.get(i);
					if(r.isConditionEquivalent(rEq)){//If a rule with the same condition clause is found
						found=true;
						manageEquivalentRule(can, rEq, r, eqClass);
					}
				}
				
				if(!found)
					eqClassList.add(r);

			}
		}
	}
	
	/**
	 * Manage equivalent rule.
	 *
	 * @param can the can
	 * @param internal the internal
	 * @param ruleToInsert the rule to insert
	 * @param eqClass the eq class
	 * @throws NoExternalDataException the no external data exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws SecurityException the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws ClassNotFoundException the class not found exception
	 * @throws NoSuchMethodException the no such method exception
	 * @throws InstantiationException the instantiation exception
	 * @throws IllegalAccessException the illegal access exception
	 * @throws InvocationTargetException the invocation target exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private void manageEquivalentRule(CanonicalForm can, GenericRule internal, GenericRule ruleToInsert, long eqClass) throws NoExternalDataException, InvalidActionException, SecurityException, IllegalArgumentException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, IOException {
		IndexingBitSet bsInternal = canLabels.get(internal);
		IndexingBitSet bsToInsert = canLabels.get(ruleToInsert);
		
		
		if (bsToInsert.hasAtLeastTheSameBitsAs(bsInternal)){//As at list the same rules
			canLabels.remove(internal);
			ibsLabel.remove(bsInternal);
			canRules.get(eqClass).remove(internal);
			
			canRules.get(eqClass).add(ruleToInsert);
			return;			
		}
		
		if (bsInternal.hasAtLeastTheSameBitsAs(bsToInsert)){
			canLabels.remove(ruleToInsert);
			ibsLabel.remove(bsToInsert);

			
			return;			
		}
		
		GenericRule [] rules1 = decomposeRule(ruleToInsert, can);
		GenericRule [] rules2 = decomposeRule(internal, can);
		
		LinkedList<GenericRule> ruleList = new LinkedList<GenericRule>();
		
		for (GenericRule r : rules1)
			if (r!=null)
				ruleList.add(r);
		
		for (GenericRule r : rules2)
			if (!ruleList.contains(r))
				if (r!=null)
					ruleList.add(r);
		
		

		
		List<HSPL> HSPLs = new LinkedList<>();
		HashSet<String> MSPLs = new HashSet<>();
		String name = "";
		for(GenericRule r:ruleList){
			name = name + r.getName();
			
			HSPLs.addAll(r.getHSPLs());
			MSPLs.addAll(r.getMSPL_id());
		}
		
		ConditionClause cc = ruleToInsert.getConditionClause().conditionClauseClone();
		cc.intersection(internal.getConditionClause());
		
		GenericRule newRule = new GenericRule(can.getResolutionStrategy().composeActions(ruleList), cc, name, MSPLs, HSPLs);
		
		IndexingBitSet newBs = (IndexingBitSet) bsInternal.clone();
		newBs.or(bsToInsert);
		
		canLabels.remove(ruleToInsert);
		ibsLabel.remove(bsToInsert);
		canLabels.remove(internal);
		ibsLabel.remove(bsInternal);
		canRules.get(eqClass).remove(internal);
		
		canRules.get(eqClass).add(newRule);
		canLabels.put(newRule, newBs);
		ibsLabel.put(newBs, newRule);

	}

	/**
	 * Gets the canonical form.
	 *
	 * @return the canonical form
	 */
	public CanonicalForm getCanonicalForm() {	
		return can;
	}
	
	
	
	
	
	
	
}
