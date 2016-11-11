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
package eu.fp7.secured.MultiUserConflictAnalysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.swing.plaf.SliderUI;
import javax.xml.bind.DatatypeConverter;

import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.mspl.CapabilityType;
import eu.fp7.secured.mspl.FilteringCapability;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.tools.Analyzer;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalFormGenerator;
import eu.fp7.secured.policy.translation.morphisms.FMRMorphism;
import eu.fp7.secured.policy.translation.semilattice.SemiLatticeGenerator;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.reconciliation.ReconciliationResult;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.utils.HTMLView;
import eu.fp7.secured.utils.PolicyWrapper;
import eu.fp7.secured.xml.Edge;
import eu.fp7.secured.xml.Mapping;
import eu.fp7.secured.xml.Service;
import eu.fp7.secured.xml.ServiceGraph;

/**
 * The Class MultiUserConflictAnalysisHTML.
 */
public class MultiUserConflictAnalysisHTML {

	/**
	 * Analyse.
	 *
	 * @param coop_creator the coop_creator
	 * @param coop_app_graph the coop_app_graph
	 * @param MSPLs the MSP ls
	 * @return the string
	 * @throws Exception the exception
	 */
	public static String analyse(LinkedList<String>  coop_creator, LinkedList<String> coop_app_graph, LinkedList<String> MSPLs) throws Exception{


		LinkedList<Policy> nc_list = new LinkedList<>();
		LinkedList<Policy> p_list = new LinkedList<>();
		LinkedList<Policy> p_list_c = new LinkedList<>();
		HashMap<String, LinkedList<Policy>> rp_list = new HashMap<>();
		HashMap<String, Service> sg_list = new HashMap<>();
		LinkedList<Policy> r_list = new LinkedList<>();
		LinkedList<Policy> r_list_c = new LinkedList<>();
		LinkedList<Policy> u_list = new LinkedList<>();
		HashSet<String> HSPLs = new HashSet<>();
		HashMap<String, ITResource> itr_map = new HashMap<>();
		Mapping map = new Mapping();
		map.setServiceGraph(new ServiceGraph());

		int i=0;

		for(String p:MSPLs){
			ITResource itr = PolicyWrapper.getITResource(new String(DatatypeConverter.parseBase64Binary(p)));
			itr_map.put(itr.getID(), itr);
		}

		i=0;
		for (String ap : coop_app_graph) {
			ServiceGraph sg = PolicyWrapper.getServiceGraph(new String(DatatypeConverter.parseBase64Binary(ap)));
			for(Service s:sg.getService()){
				String msplid = s.getPSA().getMSPLList().getMsplList().get(0).getId();
				ITResource itr = itr_map.get(msplid);
				Policy p = PolicyWrapper.getPolicy(itr, coop_creator.get(i));

				String sID = s.getPSA().getCapability().getCapabilityList().toString();

				if(!rp_list.containsKey(sID)){
					rp_list.put(sID, new LinkedList<Policy>());
					sg_list.put(sID, s);
				}

				rp_list.get(sID).add(p);
				p_list.add(p);

				if(i==coop_app_graph.size()-1){
					u_list.add(p);
					for(GenericRule r:p.getRuleSet()){
						for(HSPL h:r.getHSPLs())
							HSPLs.add(h.getHSPLId());
					}
				}

				p_list_c.add(PolicyWrapper.getPolicy(itr, coop_creator.get(i)));
			}
			i++;
		}



		i=0;
		Service sid = null;
		for(String rps:rp_list.keySet()){
			String name = "MSPL_"+UUID.randomUUID().toString();
			r_list.add(getReconciledPolicy(name, rp_list.get(rps)));
			File file = new File(name);
			r_list_c.add(PolicyWrapper.getPolicy(file, "RECONCILIATION"));
			file.delete();

			Service service = sg_list.get(rps);
			service.getPSA().getMSPLList().getMsplList().get(0).setId(name);
			map.getServiceGraph().getService().add(service);

			if(sid != null){
				Edge e = new Edge();
				e.setSrcService(sid);
				e.setDstService(service);
				map.getServiceGraph().getEdge().add(e);
			}

			if(i==0){
				map.getServiceGraph().setRootService(service);
				sid = service;
			}
			if(i==rp_list.size()-1){
				map.getServiceGraph().setEndService(service);
			}

			sid = service;
			i++;
		}

		LinkedList<LinkedList<Policy>> policy_list = new LinkedList<>();
		LinkedList<Policy> an_p_list = new LinkedList<>();
		an_p_list.addAll(r_list);
		an_p_list.addAll(nc_list);
		policy_list.add(an_p_list);
		policy_list.add(u_list);

		Collection<PolicyAnomaly> anomalies = distributedAnalysis(policy_list, nc_list);




		return new String(DatatypeConverter.printBase64Binary(HTMLView.createHTMLView(anomalies, coop_creator, null, HSPLs, p_list_c, r_list_c, "MUCA",  "Multi User Conflict Analysis Report report", "Multi User Conflict Analysis Report statisctics").getBytes()));

	}

	/**
	 * Gets the reconciled policy.
	 *
	 * @param filename the filename
	 * @param policies the policies
	 * @return the reconciled policy
	 * @throws Exception the exception
	 */
	private static Policy getReconciledPolicy(String filename, LinkedList<Policy> policies) throws Exception {
		LinkedList<LinkedList<Policy>> policy_list = new LinkedList<LinkedList<Policy>>();

		policy_list.add(policies);

		ComposedPolicy policy = new ComposedPolicy(policy_list,	new LinkedList<Capability>(), "ComposedPolicy", "RECONCILIATION");

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		CanonicalFormGenerator can_gen = CanonicalFormGenerator.getInstance(policy, selectorTypes);
		can_gen.generateClosure();
		CanonicalForm can = can_gen.getCanonicalForm();
		SemiLatticeGenerator slgen = new SemiLatticeGenerator();
		slgen.generateSemilattice(can);
		FMRMorphism fmr = new FMRMorphism(can);
		List<GenericRule> rules = fmr.exportRules();

		PolicyWrapper.writePolicy(filename, rules, policies.get(0).getCapability(), FilteringAction.ALLOW, filename);


		return PolicyWrapper.getPolicy(new File(filename), "RECONCILIATION");
	}

	/**
	 * Distributed analysis.
	 *
	 * @param policy_list the policy_list
	 * @param nc_policies the nc_policies
	 * @return the collection
	 * @throws Exception the exception
	 */
	private static Collection<PolicyAnomaly> distributedAnalysis(LinkedList<LinkedList<Policy>> policy_list, LinkedList<Policy> nc_policies) throws Exception {

		ComposedPolicy policy = new ComposedPolicy(policy_list,new LinkedList<Capability>(), "ComposedPolicy", "RECONCILIATION");

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		Analyzer analyzer = new Analyzer();

		CanonicalFormGenerator can_gen = CanonicalFormGenerator.getInstance(
				policy, selectorTypes);
		can_gen.generateClosure();
		CanonicalForm can = can_gen.getCanonicalForm();
		SemiLatticeGenerator slgen = new SemiLatticeGenerator();
		slgen.generateSemilattice(can);


		HashMap<GenericRule, PolicyAnomaly> rule_anomalies = new HashMap<>();
		LinkedHashMap<String, Selector> selectors = new LinkedHashMap<>();
		ConditionClause cc = new ConditionClause(selectors);


		HashMap<Policy, GenericRule> nc_rules = new HashMap<>();
		for (Policy p : nc_policies) {
			GenericRule nc_rule = new GenericRule(FilteringAction.DENY, cc, "NON-COOPERATIVE POLICY : "+p.getName()+" defined by "+p.getCreator(), null, null);
			nc_rules.put(p, nc_rule);
		}

		for (PolicyAnomaly a : analyzer.getDistributedAnomalies(policy, can,
				can.getSemiLattice())) {
			if (a.getConflict().equals(ConflictType.INCONSISTENT)) {

				for (GenericRule r : a.getRule_set()) {
					boolean found = false;
					for (Policy p : policy_list.getLast()) {
						if (p.containsRule(r)) {
							found = true;
						}
					}

					if (!found) {
						found = false;
						for (Policy p : nc_policies) {
							if (p.containsRule(r)) {
								r = nc_rules.get(p);
							}
						}



						HashSet<GenericRule> ano_rules = new HashSet<>();
						if (rule_anomalies.containsKey(r)) {
							for (GenericRule ar : rule_anomalies.get(r).getRule_set()){
								ano_rules.add(ar);
							}
							rule_anomalies.remove(r);
						}
						for (GenericRule ar : a.getRule_set()) {

							found = false;
							for (Policy p : policy_list.getLast())
								if (p.containsRule(ar))
									found = true;
							if (found){
								ano_rules.add(ar);
							}
						}

						ano_rules.add(r);

						GenericRule[] ano_r = new GenericRule[ano_rules.size()];

						ano_r[0] = r;
						int i=1;
						for(GenericRule rr:ano_rules){
							if(!r.equals(rr))
								ano_r[i++] = rr;
						}

						PolicyAnomaly ano = new PolicyAnomaly(policy.getOriginalPolicy(), ano_r, ConflictType.INCONSISTENT);
						rule_anomalies.put(r, ano);
					}
				}

			}
		}

		return rule_anomalies.values();
	}
}
