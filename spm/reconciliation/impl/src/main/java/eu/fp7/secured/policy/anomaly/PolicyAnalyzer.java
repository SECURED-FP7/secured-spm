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
package eu.fp7.secured.policy.anomaly;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.EmptySelectorException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.MultiPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.ExternalDataResolutionStrategy;
import eu.fp7.secured.policy.resolution.GenericConflictResolutionStrategy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.GenericRule;


// il policy analyzer pu� funzionare perch� all'interno di una policy
// con le attuali strategie di risoluzione � possibile trovare un ordinamento
// quasi-totale ma consistente

/**
 * The Class PolicyAnalyzer.
 */
public class PolicyAnalyzer {
	
	/** The resolution strategy. */
	private GenericConflictResolutionStrategy resolutionStrategy;
	
	/** The default action. */
	private Action defaultAction; 
	
	/** The comparator. */
	private ECComparator comparator;
	
	/** The rule comparator. */
	private RuleComparator ruleComparator;
	
	/** The ordered_list_rules. */
	private ArrayList<GenericRule> ordered_list_rules = null;
		
	/** The equivalence_classes. */
	private ArrayList<ArrayList<GenericRule>> equivalence_classes = null;
	
	/** The reduced_equivalence_classes. */
	private ArrayList<ArrayList<GenericRule>> reduced_equivalence_classes = null;
	
	/** The necessary_rules. */
	private ArrayList<GenericRule> necessary_rules;
	
	/** The unnecessary_rules. */
	private ArrayList<GenericRule> unnecessary_rules;
	
	/** The policy. */
	private Policy policy;
	
	/** The classifier. */
	private RuleAnomalyAnalyzer classifier;
	
	/** The Constant REDUNDANCY_TEST. */
	private static final boolean REDUNDANCY_TEST = false;
	
	/** The Constant CHECK_N_HIDDEN. */
	private static final boolean CHECK_N_HIDDEN = true;
	
	/** The Constant SORT_RULE_LISTS. */
	private static final boolean SORT_RULE_LISTS = true;	
	
	/** The analizer_list. */
	private List<PolicyAnalyzer> analizer_list;
	
	/** The remove non subnet rules. */
	private boolean REMOVE_NON_SUBNET_RULES = false;
	
	/** The source_subnet. */
	private GenericRule source_subnet;
	
	/** The dest_subnet. */
	private GenericRule dest_subnet;
	
	
	/**
	 * Instantiates a new policy analyzer.
	 *
	 * @param policy the policy
	 * @param selectorTypes the selector types
	 */
	public PolicyAnalyzer(Policy policy, SelectorTypes selectorTypes) {
		this.policy = policy;
		this.resolutionStrategy  = policy.getResolutionStrategy();
		this.classifier 		 = new RuleAnomalyAnalyzer(policy, selectorTypes);
		
		this.comparator 		 = new ECComparator(policy);
		this.ruleComparator 	 = new RuleComparator(this.policy);
		
		this.analizer_list = null;
		if(policy instanceof MultiPolicy){
			this.analizer_list = new LinkedList<PolicyAnalyzer>();
			for(Policy p:((MultiPolicy)policy).getPolicyList()){
				this.analizer_list.add(new PolicyAnalyzer(p,selectorTypes));
			}
		}
		if(policy instanceof ComposedPolicy){
			this.analizer_list = new LinkedList<PolicyAnalyzer>();
			for(Policy p:((ComposedPolicy)policy).getOriginalPolicy()){
				this.analizer_list.add(new PolicyAnalyzer(p,selectorTypes));
			}
			if(((ComposedPolicy)policy).getSourceSubnet()!=null){
				setSourceSubnet(((ComposedPolicy)policy).getSourceSubnet());
				for(PolicyAnalyzer a:this.analizer_list)
					a.setSourceSubnet(source_subnet);
			}
			if(((ComposedPolicy)policy).getDestSubnet()!=null){
				setDestSubnet(((ComposedPolicy)policy).getDestSubnet());
				for(PolicyAnalyzer a:this.analizer_list)
					a.setDestSubnet(dest_subnet);
			}
		}
	}
	
	
//	public List<GenericRule> getOrderedRules(){
//		//TODO Quale ordine seguire?? ha senso per composed? A cosa serve?
//		if (ordered_list_rules==null)
//			ordered_list_rules = new ArrayList<GenericRule>();
//			
//		if(analizer_list!=null){
//			for(PolicyAnalyzer a:analizer_list){
//				ordered_list_rules.addAll(a.getOrderedRules());
//			}
//		} else orderRules();
//		
//		return ordered_list_rules;
//	}
	
	/**
 * Sets the source subnet.
 *
 * @param subnet the new source subnet
 */
private void setSourceSubnet(GenericRule subnet) {
		REMOVE_NON_SUBNET_RULES=true;
		this.source_subnet=subnet;
	}
	
	/**
	 * Sets the dest subnet.
	 *
	 * @param subnet the new dest subnet
	 */
	private void setDestSubnet(GenericRule subnet) {
		REMOVE_NON_SUBNET_RULES=true;
		this.dest_subnet=subnet;
	}
	
	/**
	 * Order rules.
	 */
	private void orderRules(){
		if(ordered_list_rules == null)
			ordered_list_rules = new ArrayList<GenericRule>(this.policy.size());
		
		
		Set<GenericRule> toadd = policy.getRuleSet();
		
		ordered_list_rules.addAll(toadd);
		
		Collections.sort(ordered_list_rules, ruleComparator);
		
	}
	
	
	/**
	 * Reduce ec.
	 *
	 * @param toremove the toremove
	 */
	private void reduceEC(Collection<GenericRule> toremove){
		List<GenericRule> listtoremove = null;
		
		for(GenericRule r: toremove){
			for(List<GenericRule> l: reduced_equivalence_classes){
				if(l.contains(r)){
					listtoremove = l;
					break;
				}
			}
			if(listtoremove != null)
				reduced_equivalence_classes.remove(listtoremove);
		}
		
	}
	
/**
 * Calculate_necessary_rules.
 */
//	@SuppressWarnings("unchecked")
	@SuppressWarnings("unchecked")
	private void calculate_necessary_rules(){
		
//		if(necessary_rules == null){
		try {
			this.necessary_rules = new ArrayList<GenericRule>(this.policy.size());
			this.unnecessary_rules = new ArrayList<GenericRule>(this.policy.size());
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		
//	}
		
		
		
		calculateEquivalenceClasses();
		
		int max;
		int N = equivalence_classes.size();
		try {
			
			/* 
			 * blocco 1 ec per ogni regola
			 * es. FMR
			 */
			if(N == this.policy.size()){
//				System.out.println("Caso tante EC (FMR)");

				orderRules();
				reduced_equivalence_classes = (ArrayList<ArrayList<GenericRule>>) equivalence_classes.clone();
				
				
				
				boolean toinsert;
				for(GenericRule r1: ordered_list_rules){
					toinsert = true;
					for(GenericRule r2: necessary_rules){
						if(classifier.isHidden(r1, r2)){
							toinsert = false;
							break;
						}
					}
					if(toinsert)
						necessary_rules.add(r1);
					else
						unnecessary_rules.add(r1);
				}
				
				max = necessary_rules.size();
				if(max == 1)
					return;
				
				HashSet<GenericRule> toremove = new HashSet<GenericRule>();
				for(int i = 1; i < max; i++){
					if(classifier.isRedundant(necessary_rules.get(i-1), necessary_rules.get(i)))
						toremove.add(necessary_rules.get(i-1));
				}
				
				necessary_rules.removeAll(toremove);
				unnecessary_rules.addAll(toremove);
				
				reduceEC(unnecessary_rules);
				
			}
			
			else{
				/*
				 * caso |equivalent_classes| < |policy.size|
				 * es. DTP/ATP 
				 */
				
//				max = equivalence_classes.size();			

				reduced_equivalence_classes = new ArrayList<ArrayList<GenericRule>>(N);
				
				for(int i =0; i < N; i++){
					intraECAnalysis(i, reduced_equivalence_classes);				
				}
				
				
				if(REDUNDANCY_TEST && N != 1){
					for(int i = 1; i < N; i++){
						redundantElimination(reduced_equivalence_classes.get(i-1), reduced_equivalence_classes.get(i-1));
					}
				}
				
				// c'� di sicuro almeno una classe di equivalenza
				necessary_rules.addAll(reduced_equivalence_classes.get(0));
				
				ArrayList<GenericRule> toinsertList = new ArrayList<GenericRule>();
				ArrayList<GenericRule> toremoveList = new ArrayList<GenericRule>();
				boolean toinsert;
				for(int i = 1; i < N; i++){
					toinsertList.clear();
					toremoveList.clear();
					for(GenericRule r1: reduced_equivalence_classes.get(i)){
						toinsert = true;
						for(GenericRule r2: necessary_rules){
							if(classifier.isHiddenOrEquivalent(r1, r2)){
								toinsert = false;
								break;
							}
						}
						if(toinsert)
							toinsertList.add(r1);
						else{
							unnecessary_rules.add(r1);
							toremoveList.add(r1);
						}
					}
					reduced_equivalence_classes.get(i).removeAll(toremoveList);
					necessary_rules.addAll(toinsertList);
				}
			}
			if(CHECK_N_HIDDEN){
				max = necessary_rules.size();
				List<GenericRule> toremove = new ArrayList<GenericRule>();
				for(int i=1; i < max; i++){
//					List<GenericRule> tocheck = new LinkedList<GenericRule>(necessary_rules.subList(0, i-1));
//					tocheck.addAll(necessary_rules.subList(i, max));
//					
//					if(checkNHidden(necessary_rules.get(i), tocheck)){
//						toremove.add(necessary_rules.get(i));
//					}
					if(checkNHidden(necessary_rules.get(i), necessary_rules.subList(0, i-1))){
						toremove.add(necessary_rules.get(i));
					}
				}
				necessary_rules.removeAll(toremove);
				unnecessary_rules.addAll(toremove);
				for(ArrayList<GenericRule> l: reduced_equivalence_classes){
					l.removeAll(toremove);
				}
			}
			if(REMOVE_NON_SUBNET_RULES){
				List<GenericRule> toremove = new ArrayList<GenericRule>();
				for(GenericRule r:necessary_rules){
					if(!r.isIntersecting(source_subnet) && !r.isIntersecting(dest_subnet)){
						toremove.add(r);
					}
				}
				necessary_rules.removeAll(toremove);
				unnecessary_rules.addAll(toremove);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
		
		
		if(SORT_RULE_LISTS){
			Collections.sort(necessary_rules, ruleComparator);
			Collections.sort(unnecessary_rules, ruleComparator);
		}
		
		ArrayList<ArrayList<GenericRule>> liststoremove = new ArrayList<ArrayList<GenericRule>>();
		for(ArrayList<GenericRule> l: reduced_equivalence_classes)
			if(l.isEmpty())
				liststoremove.add(l);
		reduced_equivalence_classes.removeAll(liststoremove);
				
	}
	
	
//	/**
//	 * @return the reduced_equivalence_classes
//	 */
//	public List<ArrayList<GenericRule>> getReduced_equivalence_classes() {
//		//TODO come trattare con COMPOSED policy??
//		calculate_necessary_rules();
//		return reduced_equivalence_classes;
//	}


	/**
 * Intra ec analysis.
 *
 * @param i the i
 * @param ECclone the e cclone
 */
private void intraECAnalysis(int i, ArrayList<ArrayList<GenericRule>> ECclone){
		ArrayList<GenericRule> EC = equivalence_classes.get(i);
		ArrayList<GenericRule> result = new ArrayList<GenericRule>(EC);
		
		try {
			boolean remove_flag;
			for(GenericRule r1: EC) {
				remove_flag = false;
				for (GenericRule r2: result) {
					if (r1.equals(r2))
						continue;
					if (classifier.isHiddenOrEquivalent(r1, r2)) {
						remove_flag = true;
						break;
					}
				}
				if(remove_flag){
					result.remove(r1);
					unnecessary_rules.add(r1);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		ECclone.add(i,result);
	}
	
	/**
	 * Redundant elimination.
	 *
	 * @param greater the greater
	 * @param less the less
	 */
	private void redundantElimination(List<GenericRule> greater, List<GenericRule> less){
		
		try {
			boolean flag = false;
			int i = 0;
			for (GenericRule l : less) {
				for (GenericRule g: greater) {
					if (classifier.isRedundant(g, l)) {
						flag = true;
						break;
					}
				}
				if (flag)
					greater.remove(i);
				i++;
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * Check n hidden.
	 *
	 * @param rule the rule
	 * @param collection the collection
	 * @return true, if successful
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws DuplicatedRuleException the duplicated rule exception
	 * @throws UnmanagedRuleException the unmanaged rule exception
	 */
	private boolean checkNHidden(GenericRule rule, Collection<GenericRule> collection) throws UnsupportedSelectorException, NoExternalDataException, DuplicatedRuleException, UnmanagedRuleException{
		if(rule.isEmpty())
			return true;
		
		LinkedList<GenericRule> new_coll = new LinkedList<GenericRule>();
		
		for(GenericRule item: collection){
			ResolutionComparison comp = null;
			try {
				comp = resolutionStrategy.compare(item,rule);
			} catch (NoExternalDataException e) {
				e.printStackTrace();
			} catch (DuplicatedRuleException e) {
				e.printStackTrace();
			} catch (UnmanagedRuleException e) {
				e.printStackTrace();
			}
			if( comp == ResolutionComparison.UNIVERSALLY_LESS ) 
				continue;
			else
				new_coll.add(item);
		}
		
		boolean res = false;
		try {
			res = policy.getRuleClassifier().isHidden(rule, new_coll.toArray(new GenericRule[new_coll.size()]));
		} catch (ArrayIndexOutOfBoundsException ea){
			ea.printStackTrace();
			System.err.println("======Checking=======");
			System.err.println(rule);
			System.err.println("======Collection=======");
			for (GenericRule r : new_coll){
				System.err.println(r);
				System.err.println("-----------");
			}
			System.exit(-1);
		}
		
		return res;

	}
			
//	public List<ArrayList<GenericRule>> getEquivalenceClasses(){
//		//TODO COMPOSED POLICY: come trattare equivalence classes??
//		calculateEquivalenceClasses();
//		List<ArrayList<GenericRule>> res = equivalence_classes;
//		return res;
//	}
	
	/**
 * Calculate equivalence classes.
 */
private void calculateEquivalenceClasses(){
		
		if(equivalence_classes == null)
			equivalence_classes = new ArrayList<ArrayList<GenericRule>>();
		
		try {
			
			boolean inserted;
			
			for(GenericRule rule:policy.getRuleSet()){
				inserted = false;
				for(List<GenericRule> cl: equivalence_classes){
					
						if(resolutionStrategy.compare(rule, cl.get(0)) == ResolutionComparison.EQUIVALENT){
							cl.add(rule);
							inserted = true;
							break;
						}
				}
				if(!inserted){
					ArrayList<GenericRule> array = new ArrayList<GenericRule>();
					array.add(rule);
					equivalence_classes.add(array);
					}
				}
			
			
		} catch (NoExternalDataException e) {
			e.printStackTrace();
		} catch (DuplicatedRuleException e) {
			e.printStackTrace();
		} catch (UnmanagedRuleException e) {
			e.printStackTrace();
		}

		
		Collections.sort(equivalence_classes, comparator);

	}	

	/**
	 * Gets the necessary rules.
	 *
	 * @return the necessary rules
	 */
	public List<GenericRule> getNecessaryRules(){
		if (necessary_rules==null)
			necessary_rules = new ArrayList<GenericRule>();
		else necessary_rules.clear();
		
		if (unnecessary_rules==null)
			unnecessary_rules = new ArrayList<GenericRule>();
		else unnecessary_rules.clear();
		
		if(analizer_list!=null){
			for(PolicyAnalyzer a:analizer_list){
				necessary_rules.addAll(a.getNecessaryRules());
			}
		} else calculate_necessary_rules();
		
		return necessary_rules;
	}
	
//	public List<GenericRule> getNecessaryRules(Collection<GenericRule> rules) throws Exception {
//		calculate_necessary_rules();
//		return necessary_rules;
//	}

	/**
 * Gets the unnecessary rules.
 *
 * @return the unnecessary rules
 */
public List<GenericRule> getUnnecessaryRules()  {
		if (necessary_rules==null)
			necessary_rules = new ArrayList<GenericRule>();
		else necessary_rules.clear();
		
		if (unnecessary_rules==null)
			unnecessary_rules = new ArrayList<GenericRule>();
		else unnecessary_rules.clear();
		
		necessary_rules.clear();
		unnecessary_rules.clear();
		
		if(analizer_list!=null){
			for(PolicyAnalyzer a:analizer_list){
				unnecessary_rules.addAll(a.getUnnecessaryRules());
			}
		} else calculate_necessary_rules();
		
		return unnecessary_rules;
	}
	
//	public List<GenericRule> getUnnecessaryRules(Collection<GenericRule> rules) throws Exception {
//		calculate_necessary_rules(rules);
//		return unnecessary_rules;
//	}
//	
//	
	
	
	
	
	
	/**
 * Prints the ordered rules.
 */
public void printOrderedRules(){
		StringBuffer buf = new StringBuffer();
		buf.append("----BEGIN POLICY---------------------------------\n");
		buf.append("Resolution Strategy: " + resolutionStrategy + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Default Action: " + defaultAction + "\n");
		buf.append("-------------------------------------------------\n");
		try {
			buf.append("Rules (Total "+this.policy.size() + "): \n");
		} catch (Exception e) {
			e.printStackTrace();
		}
		orderRules();
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			@SuppressWarnings("unchecked")
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule,?>) resolutionStrategy;
			for(GenericRule rule: ordered_list_rules){
				buf.append(rule + "-->" + (ext.getExternalData(rule)) + "\n");
			}		
		}
		else for(GenericRule rule: ordered_list_rules){
			buf.append(rule);
		}
		buf.append("\n----END POLICY-----------------------------------\n");
		System.out.println(buf);
		}
	
	/**
	 * Prints the equivalence classes.
	 */
	public void printEquivalenceClasses(){
		StringBuffer buf = new StringBuffer();
		buf.append("----BEGIN POLICY---------------------------------\n");
		buf.append("Resolution Strategy: " + resolutionStrategy + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Default Action: " + defaultAction + "\n");
		buf.append("-------------------------------------------------\n");
		calculateEquivalenceClasses();
		try {
			buf.append("Rules (Total "+this.policy.size() + "): " +
					"\n---------- Equivalence Classes ("+equivalence_classes.size() + ")--------\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			@SuppressWarnings("unchecked")
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule,?>) resolutionStrategy;
			for(List<GenericRule> list: equivalence_classes){
				for(GenericRule rule: list){
					buf.append("\n"+rule + "-->" + (ext.getExternalData(rule)));
				}
				buf.append("\n----------------------------------");
			}
		}
		else for(List<GenericRule> list: equivalence_classes){
			buf.append("\n---- Elements: "+ list.size() + " ------------------\n");
			for(GenericRule rule: list){
				buf.append(rule);
				}
			buf.append("\n----------------------------------");
		}

		buf.append("\n----END POLICY-----------------------------------\n");
		System.out.println(buf);
		}
	
	/**
	 * Prints the reduced equivalence classes.
	 */
	public void printReducedEquivalenceClasses(){
		StringBuffer buf = new StringBuffer();
		buf.append("----BEGIN POLICY---------------------------------\n");
		buf.append("Resolution Strategy: " + resolutionStrategy + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Default Action: " + defaultAction + "\n");
		buf.append("-------------------------------------------------\n");
		calculate_necessary_rules();
		try {
			buf.append("Rules (Total "+this.policy.size() + "): " +
					"\n---------- Equivalence Classes ("+reduced_equivalence_classes.size() + ")--------\n");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			@SuppressWarnings("unchecked")
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule,?>) resolutionStrategy;
			for(List<GenericRule> list: reduced_equivalence_classes){
				for(GenericRule rule: list){
					buf.append("\n"+rule + "-->" + (ext.getExternalData(rule)));
				}
				buf.append("\n----------------------------------");
			}
		}
		else for(List<GenericRule> list: reduced_equivalence_classes){
			buf.append("\n---- Elements: "+ list.size() + " ------------------\n");
			for(GenericRule rule: list){
				buf.append(rule);
				}
			buf.append("\n----------------------------------");
		}

		buf.append("\n----END POLICY-----------------------------------\n");
		System.out.println(buf);
		}

	/**
	 * Prints the pre analysis results.
	 */
	public void printPreAnalysisResults(){

		try {
			calculate_necessary_rules();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		StringBuffer buf = new StringBuffer();
		buf.append("----BEGIN POLICY---------------------------------\n");
		buf.append("Resolution Strategy: " + resolutionStrategy + "\n");
		buf.append("-------------------------------------------------\n");
		buf.append("Default Action: " + defaultAction + "\n");
		buf.append("-------------------------------------------------\n");
		try {
			buf.append("Rules (Total "+this.policy.size() + "): \n");
		} catch (Exception e) {
			e.printStackTrace();
		}
		buf.append("------ NECESSARY RULES ----------\n");
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			@SuppressWarnings("unchecked")
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule,?>) resolutionStrategy;
			for(GenericRule rule: necessary_rules){
				buf.append(rule + "-->" + (ext.getExternalData(rule)) + "\n");
			}		
		}
		else for(GenericRule rule: necessary_rules){
			buf.append(rule);
		}
		buf.append("----- UNNECESSARY RULES ---------\n");
		if (resolutionStrategy instanceof ExternalDataResolutionStrategy) {
			@SuppressWarnings("unchecked")
			ExternalDataResolutionStrategy<GenericRule, ?> ext = (ExternalDataResolutionStrategy<GenericRule,?>) resolutionStrategy;
			for(GenericRule rule: unnecessary_rules){
				buf.append(rule + "-->" + (ext.getExternalData(rule)) + "\n");
			}		
		}
		else for(GenericRule rule: unnecessary_rules){
			buf.append(rule);
		}
		buf.append("----- NECESSARY STAT -----------\n");
		buf.append("necessary rules: " + necessary_rules.size());
		buf.append("\n----- UNNECESSARY STAT ---------\n");
		buf.append("Unnecessary rules: " + unnecessary_rules.size());
		buf.append("\n----END POLICY-----------------------------------\n");
		
		
		System.out.println(buf);
		}

}


class ECComparator implements Comparator<List<GenericRule>>{
	
	GenericConflictResolutionStrategy resolutionStrategy;
	
	public ECComparator(Policy policy){
		this.resolutionStrategy = policy.getResolutionStrategy();
	}

	@Override
	public int compare(List<GenericRule> list1, List<GenericRule> list2) {
		GenericRule r1 = list1.get(0);
		GenericRule r2 = list2.get(0);
		
		ResolutionComparison comp = null;
		try {
			comp = resolutionStrategy.compare(r1, r2);
			
		} catch (NoExternalDataException e) {
			e.printStackTrace();
		} catch (DuplicatedRuleException e) {
			e.printStackTrace();
		} catch (UnmanagedRuleException e) {
			e.printStackTrace();
		}
		
		if (comp == ResolutionComparison.UNIVERSALLY_LESS) return 1;
		else if (comp == ResolutionComparison.UNIVERSALLY_GREATER) return -1;
		else return 0;

	}
}
