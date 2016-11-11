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
package eu.fp7.secured.reconciliation;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.mspl.CapabilityType;
import eu.fp7.secured.mspl.FilteringCapability;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.impl.PolicyImpl;
import eu.fp7.secured.policy.tools.Analyzer;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalFormGenerator;
import eu.fp7.secured.policy.translation.morphisms.FMRMorphism;
import eu.fp7.secured.policy.translation.semilattice.SemiLatticeGenerator;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.FilteringAction;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.utils.HTMLView;
import eu.fp7.secured.utils.PolicyWrapper;
import eu.fp7.secured.xml.Edge;
import eu.fp7.secured.xml.Mapping;
import eu.fp7.secured.xml.PSA;
import eu.fp7.secured.xml.PSACharacteristic;
import eu.fp7.secured.xml.Service;
import eu.fp7.secured.xml.ServiceGraph;
import eu.fp7.secured.xml.*;


/**
 * The Class ReconciliationHTML.
 */
public class ReconciliationHTML {

	/**
	 * Reconcile.
	 *
	 * @param coop_creator the coop_creator
	 * @param coop_app_graph the coop_app_graph
	 * @param uncoop_creator the uncoop_creator
	 * @param uncoop_app_graph the uncoop_app_graph
	 * @param MSPLs the MSP ls
	 * @return the reconciliation result
	 * @throws Exception the exception
	 */
	public static ReconciliationResult reconcile(LinkedList<String>  coop_creator, LinkedList<String> coop_app_graph, LinkedList<String>  uncoop_creator, LinkedList<String> uncoop_app_graph, LinkedList<String> MSPLs) throws Exception{

		ReconciliationResult result = new ReconciliationResult();

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
		for (String ap : uncoop_app_graph) {
			ServiceGraph sg = PolicyWrapper.getServiceGraph(new String(DatatypeConverter.parseBase64Binary(ap)));
			for(Service s:sg.getService()){
				String msplid = s.getPSA().getMSPLList().getMsplList().get(0).getId();
				ITResource itr = itr_map.get(msplid);
				Policy p = PolicyWrapper.getPolicy(itr,  uncoop_creator.get(i));
				nc_list.add(p);
			}
			i++;
		}


		result.MSPLs = new LinkedList<>();
		i=0;
		Service sid = null;
		for(String rps:rp_list.keySet()){
			String name = "MSPL_"+UUID.randomUUID().toString();
			r_list.add(getReconciledPolicy(name, rp_list.get(rps)));
			File file = new File(name);
			r_list_c.add(PolicyWrapper.getPolicy(file, "RECONCILIATION"));
			result.MSPLs.add(DatatypeConverter.printBase64Binary(PolicyWrapper.readFile(name, Charset.defaultCharset()).getBytes()));
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

//		Collection<PolicyAnomaly> anomalies = new HashSet<>();

		orderingRAG(map);
		result.app_graph = PolicyWrapper.getServiceGraphString(map);

		result.report = new String(DatatypeConverter.printBase64Binary(HTMLView.createHTMLView(anomalies, coop_creator, uncoop_creator, HSPLs, p_list_c, r_list_c, "REC",  "Reconcilation report", "Reconcilation statistics").getBytes()));

		return result;
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
		
		

		PolicyWrapper.writePolicy(filename, rules, policies.get(0).getCapability(), policy.getDefaultAction(), filename);


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


	
public static void orderingRAG(Mapping map){
	ServiceGraph s=	map.getServiceGraph();
	ServiceGraph s_ord=new ServiceGraph();
	orderingRAG (s, s_ord);
	map.setServiceGraph(s_ord);
}


public static void orderingRAG(ServiceGraph s, ServiceGraph s_ord) {
	HashMap<eu.fp7.secured.xml.Capability, HashSet<Service>> m= new HashMap();
	for(eu.fp7.secured.xml.Capability c: eu.fp7.secured.xml.Capability.values()){
		m.put(c, new HashSet<Service>());
	}

	HashSet<Service> l;
	
	for (Service ser: s.getService()){
		l=m.get(ser.getPSA().getCapability().getCapabilityList().get(0));
		l.add(ser);
	}
	
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.TIMING));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.FILTERING_L_4));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.FILTERING_DNS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.FILTERING_3_G_4_G));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.FILTERING_L_7));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.BASIC_PARENTAL_CONTROL));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ADVANCED_PARENTAL_CONTROL));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.TRAFFIC_INSPECTION_L_7));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.NETWORK_TRAFFIC_ANALYSIS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.LAWFUL_INTERCEPTION));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.AUTHORISE_ACCESS_RESURCE));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.COUNT_L_4_CONNECTION));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.COUNT_DNS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.LOGGING));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ONLINE_SECURITY_ANALYZER));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ONLINE_ANTIVIRUS_ANALYSIS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ONLINE_SECURITY_ANALYZER));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ANTI_PHISHING));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ONLINE_SPAM_ANALYSIS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.OFFLINE_MALWARE_ANALYSIS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.REDUCE_BANDWIDTH));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.COMPRESS));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.PROTECTION_INTEGRITY));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.PROTECTION_CONFIDENTIALITY));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.REENCRYPT));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.IP_SEC_PROTOCOL));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.TLS_PROTOCOL));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.D_DOS_ATTACK_PROTECTION));
	s_ord.getService().addAll(m.get(eu.fp7.secured.xml.Capability.ANONIMITY));

	
	int i=0;
	Edge e;
	Service ser_old = null;
	for (Service ser: s_ord.getService()){

		if(i==0){
			s_ord.setRootService(ser);
			ser_old=ser;
		}else{
			e=new Edge();
			e.setSrcService(ser_old);
			e.setDstService(ser);
			ser_old=ser;
			s_ord.getEdge().add(e);
		}
		if(s_ord.getService().size()==i-1){
			s_ord.setEndService(s);
		}

		i++;


	}
	
	
}
}

