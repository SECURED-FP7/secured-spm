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



public class FMRMorphism implements GenericMorphism {

	private Semilattice<GenericRule> sl;
	private GenericRule TOP,ROOT;

	/**
	 * The list of rule, the ones already included in a maximal domain are set to true
	 */
	private HashMap<GenericRule, Boolean> processed;

	/**
	 * The list of the base rules  
	 */
	private LinkedList<GenericRule> baseRules;

	private CanonicalForm can;



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
	

	@Override
	public List<GenericRule> exportRules() throws Exception {
		int candidate=0;

		processed.put(TOP,true);//The top doesn't need to be processed
		//Start form the top
		HashMap<Action,List<GenericRule>> parents = distributeByAction(TOP);

		//For each different action of the parents
		for(Action a: parents.keySet()){		
			TOP = new GenericRule(a, TOP.getConditionClause(), TOP.getName());

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
	 * @param candidate the candidate of the last iteration
	 * @param ordered the list of rules ordered by label
	 * @return the next rules to compute a maxdom
	 */
	private int findCandidate(int candidate, ArrayList<GenericRule> ordered){

		for(; candidate<ordered.size(); candidate++)
			if(!processed.get(ordered.get(candidate)).booleanValue())
				return candidate;

		return -1;
	}


	/**
	 * @param v
	 * @return the incoming vertices of v grouped by action
	 * @throws Exception
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
	 * @param start the starting vertex of the path
	 * @param end the ending vertex of the path
	 * @return true if the action in every path between start and end is homogeneous
	 * @throws NotInSemiLatticeException 
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

	class KeyComparator implements Comparator<GenericRule>{
		HashMap<GenericRule, IndexingBitSet> map;
		KeyComparator(HashMap<GenericRule, IndexingBitSet> map){
			this.map = map;
		}
		@Override
		public int compare(GenericRule r1, GenericRule r2) {	
			//System.out.println(-map.get(r1).compareTo(map.get(r2)));
			return -map.get(r1).compareTo(map.get(r2));
		}

	}

}
