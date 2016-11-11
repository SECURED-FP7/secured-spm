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
package eu.fp7.secured.policy.translation.morphisms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.NotInSemiLatticeException;
import eu.fp7.secured.exception.policy.ResolutionErrorException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.semilattice.Semilattice;
import eu.fp7.secured.policy.utils.IndexingBitSet;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;



/**
 * The Class FMRMorphism.
 */
public class FMRMorphism implements GenericMorphism {

	/** The sl. */
	private Semilattice<GenericRule> sl;
	
	/** The root. */
	private GenericRule TOP,ROOT;

	/** The processed. */
	private HashMap<GenericRule, Boolean> processed;

	/** The base rules. */
	private LinkedList<GenericRule> baseRules;

	/** The can. */
	private CanonicalForm can;



	/**
	 * Instantiates a new FMR morphism.
	 *
	 * @param can the can
	 * @throws Exception the exception
	 */
	public FMRMorphism(CanonicalForm can) throws Exception{	
		this.sl=can.getSemiLattice();
		this.TOP=sl.getTop();
		this.ROOT=sl.getRoot();
		this.can=can;


//		KeyComparator comp = new KeyComparator(can.getLabels());//Orders the rules by label

		this.processed=new HashMap<GenericRule,Boolean>();//Records the rules already processed (value=true)

		for(GenericRule r: can.getRuleSet()){
			processed.put(r,false);//All the rules are initially set to non processed
		}

		this.baseRules=new LinkedList<GenericRule>();
	}
	
	/**
	 * Instantiates a new FMR morphism.
	 *
	 * @param can the can
	 * @param rb the rb
	 * @throws Exception the exception
	 */
	public FMRMorphism(CanonicalForm can, GenericRule rb) throws Exception{	
		this.sl=can.getSemiLattice();
		this.TOP=sl.getTop();
		this.ROOT=sl.getRoot();
		this.can=can;
		
//		KeyComparator comp = new KeyComparator(can.getLabels());//Orders the rules by label

		this.processed=new HashMap<GenericRule,Boolean>();//Records the rules already processed (value=true)

		for(GenericRule r: can.getRuleSet()){//
			if(can.getLabels().get(r).hasAtLeastTheSameBitsAs(can.getLabels().get(rb)))
				processed.put(r, false);
			else
				processed.put(r, true);
		}

		this.baseRules=new LinkedList<GenericRule>();
	}
	

	/* (non-Javadoc)
	 * @see eu.fp7.secured.policy.translation.morphisms.GenericMorphism#exportRules()
	 */
	@Override
	public List<GenericRule> exportRules() throws Exception {
		int candidate=0;

		processed.put(TOP,true);//The top doesn't need to be processed
		//Start form the top
		HashMap<Action,List<GenericRule>> parents = distributeByAction(TOP);

		//For each different action of the parents
		for(Action a: parents.keySet()){		
			TOP = new GenericRule(a, TOP.getConditionClause(), TOP.getName(), null, null);

			for(GenericRule r: parents.get(a))
				if(!processed.get(r).booleanValue())
					navigateAndInsert(r, TOP);//We check against the TOP to avoid problem with dummy TOP

		}

		ArrayList<GenericRule> ordered = new ArrayList<GenericRule>(can.getRuleSet());
		KeyComparator comparator = new KeyComparator(can.getLabels());
		Collections.sort(ordered, comparator);

		candidate=findCandidate(candidate,ordered);//Get the next rule which will be inserted in a maxdom
		while(candidate>=0){
			navigateAndInsert(ordered.get(candidate),ordered.get(candidate));
			candidate=findCandidate(candidate,ordered);//Get the next rule which will be inserted in a maxdom
		}

		post_optimization(baseRules);

		return baseRules;
	}

	/**
	 * Find candidate.
	 *
	 * @param candidate the candidate
	 * @param ordered the ordered
	 * @return the int
	 */
	private int findCandidate(int candidate, ArrayList<GenericRule> ordered){

		for(; candidate<ordered.size(); candidate++)
			if(!processed.get(ordered.get(candidate)).booleanValue())
				return candidate;

		return -1;
	}


	/**
	 * Distribute by action.
	 *
	 * @param v the v
	 * @return the hash map
	 * @throws Exception the exception
	 */
	private HashMap<Action,List<GenericRule>> distributeByAction(GenericRule v) throws Exception {


		HashMap<Action,List<GenericRule>> map = new HashMap<Action,List<GenericRule>>();

		for(GenericRule v_in : sl.getIncomingAdjacentVertices(v)) {

			if(v_in.equals(ROOT))
				continue;

			Action a = v_in.getAction();
			if(map.containsKey(a))
				map.get(a).add(v_in);
			else {
				LinkedList<GenericRule> l = new LinkedList<GenericRule>();
				l.add(v_in);
				map.put(a, l);
			}
		}
		return map;
	}

	/**
	 * Navigate and insert.
	 *
	 * @param r the r
	 * @param end the end
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 */
	public void navigateAndInsert(GenericRule r, GenericRule end) throws NotInSemiLatticeException{

		boolean isBaseRule = true;

		processed.put(r,true);

		Action av = r.getAction();

		for(GenericRule v_in : sl.getIncomingAdjacentVertices(r)) {

			if(v_in.equals(ROOT))
				continue;

			if(v_in.getAction() == av) {//If it has the same action
				if(!processed.get(v_in)) {//If not yet processed
					if(verifyActionOnPath(v_in,end)){
						isBaseRule = false;//r is not a base rule because it has some parents with the same action
						navigateAndInsert(v_in, end);//Check the parent
					} 
				}
				else 
					isBaseRule = false;//r is not a base rule, because the base rule is one of its parents already processed
			} 
		}
		if(isBaseRule){
			baseRules.add(r);
		}
	}

	/**
	 * Verify action on path.
	 *
	 * @param start the start
	 * @param end the end
	 * @return true, if successful
	 * @throws NotInSemiLatticeException the not in semi lattice exception
	 */
	private boolean verifyActionOnPath(GenericRule start, GenericRule end) throws NotInSemiLatticeException{

		if(start.equals(end)) 
			return true;

		for(GenericRule v_out : sl.getOutgoingAdjacentVertices(start)) {


			if(!processed.get(v_out)){
				if(!v_out.getAction().equals(end.getAction()))
					return false;
				else
					if(!verifyActionOnPath(v_out, end))
						return false;
			}

		}
		return true;
	}

	/**
	 * Post_optimization.
	 *
	 * @param rule_list the rule_list
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 * @throws ResolutionErrorException the resolution error exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws InvalidActionException the invalid action exception
	 */
	private void post_optimization(List<GenericRule> rule_list) throws UnsupportedSelectorException, UnmanagedRuleException, ResolutionErrorException, NoExternalDataException, DuplicateExternalDataException, IncompatibleExternalDataException, InvalidActionException {

		Action def = can.getDefaultAction();
		int limit = rule_list.size();
		List<GenericRule> non_def = new LinkedList<GenericRule>();
		IndexingBitSet ibs = new IndexingBitSet();

		for(int i = limit-1; i >= 0; i--) {
			GenericRule r = rule_list.get(i);
			if(r.getAction().equals(def)) {	
				if(can.getLabels().get(r).intersects(ibs))
					continue;

				boolean to_remove = true;

				for(GenericRule r_nd: non_def) {
					try {
						//if(CF.getCFManager().isConflicting(r, r_nd)) {
						if (r.isIntersecting(r_nd) && ! can.getResolutionStrategy().isActionEquivalent(r, r_nd)){
							to_remove = false;
							break;
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				if(to_remove)
					rule_list.remove(i);
			} else {
				ibs.or(can.getLabels().get(r));
				non_def.add(r);
			}
		}
	}

	/**
	 * The Class KeyComparator.
	 */
	class KeyComparator implements Comparator<GenericRule>{
		
		/** The map. */
		HashMap<GenericRule, IndexingBitSet> map;
		
		/**
		 * Instantiates a new key comparator.
		 *
		 * @param map the map
		 */
		KeyComparator(HashMap<GenericRule, IndexingBitSet> map){
			this.map = map;
		}
		
		/* (non-Javadoc)
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@Override
		public int compare(GenericRule r1, GenericRule r2) {	
			//System.out.println(-map.get(r1).compareTo(map.get(r2)));
			return -map.get(r1).compareTo(map.get(r2));
		}

	}

}
