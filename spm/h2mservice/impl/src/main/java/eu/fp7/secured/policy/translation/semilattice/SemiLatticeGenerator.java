package eu.fp7.secured.policy.translation.semilattice;


import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

import org.jgraph.graph.DefaultEdge;

import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.utils.IndexingBitSet;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;

// TODO: Auto-generated Javadoc
/**
 * The Class SemiLatticeGenerator.
 */
public class SemiLatticeGenerator {
	
	/**
	 * Instantiates a new semi lattice generator.
	 *
	 * @param model the model
	 */
	public SemiLatticeGenerator(){
	}
	
	
	
	/**
	 * Gets the sub semi lattice.
	 *
	 * @param rule the rule
	 * @return the sub semi lattice
	 * @throws Exception the exception
	 */
	public Semilattice<GenericRule> getSubSemiLattice(Semilattice<GenericRule> sl, GenericRule rule) throws Exception {
		Semilattice<GenericRule> semilattice = new Semilattice<GenericRule>(sl.getTop(), sl.getRoot());
		
		semilattice.addVertex(sl.getRoot());
		semilattice.addVertex(sl.getTop());
		
		insertInconsisten(semilattice, sl, rule, semilattice.getRoot(), semilattice.getTop());
		
		return semilattice;
	}
	
	
	
	
	
	/**
	 * Insert inconsisten.
	 *
	 * @param semilattice the semilattice
	 * @param sl the sl
	 * @param to_insert the to_insert
	 * @param before the before
	 * @param after the after
	 * @throws Exception the exception
	 */
	private void insertInconsisten(Semilattice<GenericRule> semilattice, Semilattice<GenericRule> sl, GenericRule to_insert, GenericRule before, GenericRule after) throws Exception{
		semilattice.addVertex(to_insert);
		semilattice.addVertexBetween(to_insert, before, after);
		for(GenericRule rule:sl.getOutgoingAdjacentVertices(to_insert)){
			if(!rule.equals(sl.getTop()))
				insertInconsisten(semilattice, sl, rule, to_insert, after);
		}
	}
	
	
	
	
	
	/**
	 * Generate semilattice.
	 *
	 * @throws Exception the exception
	 */
	public void generateSemilattice(CanonicalForm can) throws Exception{
		
		if(can.getSemiLattice()!=null){
			return;
		}
		
		HashMap<GenericRule, IndexingBitSet> map = can.getLabels();
		Action defaultAction = can.getDefaultAction();
		int org_rule_num = can.getOriginalPolicy().getRuleSet().size();
		
		List<GenericRule> ordered = new ArrayList<GenericRule>(map.keySet());
		KeyComparator comparator = new KeyComparator(map);
		Collections.sort(ordered, comparator);

		
		GenericRule rTop = null, rRoot = null;
		if(map.size() == 0)
			return;

		ConditionClause cc_empty = new ConditionClause(new LinkedHashMap<String, Selector>());
		rTop = new GenericRule(defaultAction,cc_empty,"TOP");
		ConditionClause cc_full = new ConditionClause(new LinkedHashMap<String, Selector>());
		rRoot= new GenericRule(defaultAction,cc_full,"ROOT");

		
		
		Semilattice<GenericRule> sl = new Semilattice<GenericRule>(rTop,rRoot);
		sl.addVertex(rTop);
		sl.addVertex(rRoot);
		
		HashSet<GenericRule> toadd = new HashSet<GenericRule>();
		
		
		GenericRule[] origninalRules = new GenericRule[org_rule_num];
		IndexingBitSet bsr;
		HashSet<GenericRule> top_list = new HashSet<GenericRule>();
		for(GenericRule r: ordered){
			toadd.clear();
			sl.addVertex(r);
			
			bsr = map.get(r);
			
			HashSet<GenericRule> toprocess = new HashSet<GenericRule>();
			int index=bsr.nextSetBit(0);
			while(index!=-1){
				if(origninalRules[index-1]==null){
					origninalRules[index-1]=r;
					toadd.add(rRoot);
				} else
					toprocess.add(origninalRules[index-1]);
				index=bsr.nextSetBit(index+1);
			}
			
			HashSet<GenericRule> listpr = new HashSet<GenericRule>();
			while(toprocess.size()!=0){
				listpr.clear();
				for(GenericRule pr: toprocess){
					boolean ruletoadd = true;
					for(DefaultEdge de: sl.outgoingEdgesOf(pr)){
						GenericRule detarget = (GenericRule) de.getTarget();
						if(bsr.hasAtLeastTheSameBitsAs(map.get(detarget))){
							ruletoadd = false;
							listpr.add(detarget);
						}
					}
					if(ruletoadd){
						toadd.add(pr);	
					}
				}
				toprocess.clear();
				toprocess.addAll(listpr);
			}
			
			for(GenericRule rtoadd: toadd){
				top_list.remove(rtoadd);
				DefaultEdge des = new DefaultEdge();
				des.setSource(rtoadd);
				des.setTarget(r);
				sl.addEdge(rtoadd,r,des);
			}
			top_list.add(r);
		}
		
		for(GenericRule r:top_list){
			DefaultEdge des = new DefaultEdge();
			des.setSource(r);
			des.setTarget(rTop);	
			sl.addEdge(r, rTop, des);
		}
		
		
		can.setSemiLattice(sl);
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
			return map.get(r1).compareTo(map.get(r2));
		}
		
	}
	
}
