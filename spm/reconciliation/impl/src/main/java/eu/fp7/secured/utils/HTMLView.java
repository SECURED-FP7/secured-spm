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
package eu.fp7.secured.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.mspl.CapabilityType;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.impl.PolicyImpl;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;

/**
 * The Class HTMLView.
 */
public class HTMLView {

	/**
	 * Creates the html view.
	 *
	 * @param filename the filename
	 * @param anomalies the anomalies
	 * @param coop the coop
	 * @param non_coop the non_coop
	 * @param HSPLs the HSP ls
	 * @param org_policies the org_policies
	 * @param rec_policy the rec_policy
	 * @param type the type
	 * @param h1 the h1
	 * @param h2 the h2
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws InvalidActionException the invalid action exception
	 * @throws NoExternalDataException the no external data exception
	 */
	public static void createHTMLView(String filename, Collection<PolicyAnomaly> anomalies, List<String> coop, List<String> non_coop, HashSet<String> HSPLs, LinkedList<Policy> org_policies, LinkedList<Policy> rec_policy, String type, String h1, String h2) throws IOException, InvalidActionException, NoExternalDataException {
		File logFile = new File(filename);

		BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
		writer.write(createHTMLView( anomalies,  coop, non_coop, HSPLs,  org_policies,  rec_policy, type, h1, h2));
		
		writer.close();
		
	}
		
	/**
	 * Creates the html view.
	 *
	 * @param anomalies the anomalies
	 * @param coop the coop
	 * @param non_coop the non_coop
	 * @param HSPLs the HSP ls
	 * @param org_policies the org_policies
	 * @param rec_policy the rec_policy
	 * @param type the type
	 * @param h1 the h1
	 * @param h2 the h2
	 * @return the string
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws InvalidActionException the invalid action exception
	 * @throws NoExternalDataException the no external data exception
	 */
	public static String createHTMLView(Collection<PolicyAnomaly> anomalies, List<String> coop, List<String> non_coop, HashSet<String> HSPLs, LinkedList<Policy> org_policies, LinkedList<Policy> rec_policy, String type, String h1, String h2) throws IOException, InvalidActionException, NoExternalDataException {
		String report_sting = getHeader();
		report_sting +="<h1> "+h1+" </h1>\n";
		report_sting +="<HR SIZE=4 WIDTH=100% COLOR=red >\n"; 
		
		report_sting +="<FIELDSET>"
				+ "	<LEGEND>"+h2+"</LEGEND>\n";
		
				
		report_sting += getPolicyInfoHeader();
		
		int num_r = 0;
		for(Policy p:org_policies){
			num_r += p.getRuleSet().size();
		}
		HashSet<GenericRule> rule_anomalies = new HashSet<>();
		for (PolicyAnomaly anomaly : anomalies) {
			for (GenericRule rule : anomaly.getRule_set()) {
				rule_anomalies.add(rule);
			}
		}
		report_sting += getPolicyInfoBody(org_policies.size(), num_r, anomalies.size(), rule_anomalies.size(), coop, non_coop);
		report_sting += getPolicyInfoFooter();
		report_sting +="</FIELDSET>\n";
		report_sting +="</br>\n";
		report_sting +="</br>\n";
		

		report_sting += getHSPLTree(anomalies, rec_policy, HSPLs, type);
		report_sting +="</br>\n";
		
		
		if(type.equals("SUCAS") || type.equals("SUCAD"))
			report_sting += getPolicyTree(org_policies,"treeview2", "User policies");
		if(type.equals("MUCA"))
			report_sting += getPolicyTree(org_policies,"treeview2", "User-Stack policies");
		if(type.equals("REC"))
			report_sting += getPolicyTree(org_policies,"treeview2", " Policies considered by the reconciliation process");
		report_sting +="</br>\n";
		if(type.equals("REC")){
			report_sting += getConflictTree(anomalies, rec_policy, "REC_C");
			report_sting += getConflictTree(anomalies, rec_policy, "REC_UC");
		} else {
			report_sting += getConflictTree(anomalies, rec_policy, type);
		}
		report_sting +="</br>\n";
		if(rec_policy!=null && type.equals("REC"))
			report_sting += getPolicyTree(rec_policy,"treeview3", "Reconciled policy");
		if(rec_policy!=null && type.equals("MUCA"))
			report_sting += getPolicyTree(rec_policy,"treeview3", "Reconciled policy (User-Stack)");
		
		report_sting += getFooter();
		
		return report_sting;		
	}
	
	/**
	 * Gets the policy tree.
	 *
	 * @param policies the policies
	 * @param id the id
	 * @param name the name
	 * @return the policy tree
	 */
	private static String getPolicyTree(LinkedList<Policy> policies, String id, String name) {
		String report_sting = getTreeHeader(id, name, "rootfolder");
		
		String rstring = report_sting;
		Boolean foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: L3_filtering","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.FILTERING_L_4)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: L7_filtering","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.FILTERING_L_7)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: IPsec","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.IP_SEC_PROTOCOL)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Advanced parental control","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.ADVANCED_PARENTAL_CONTROL)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Reduce bandwidth","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.REDUCE_BANDWIDTH)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Anonimity","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.ANONIMITY)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Anti-Malware","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.OFFLINE_MALWARE_ANALYSIS)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Logging","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.LOGGING)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: antiPhishing","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.ANTI_PHISHING)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		rstring = report_sting;
		foundc = false;
		report_sting += getTreeBodyHeader("CAPABILITY: Reencrypt","capability");	
		for (Policy policy : policies) {
			boolean found = false;
			for(Capability cap:policy.getCapability()){
				if(cap.getName()==CapabilityType.REENCRYPT)
					found = true;
			}
			if(found){
				foundc=true;
				report_sting += getPolicy(policy);
			}
		}
		report_sting += getTreeBodyFooter();
		if(!foundc)
			report_sting = rstring;
		
		report_sting += getTreeFooter();
		return report_sting;
	}
	
	/**
	 * Gets the policy.
	 *
	 * @param policy the policy
	 * @return the policy
	 */
	private static String getPolicy(Policy policy){
		String report_sting="";
		if(!policy.getCreator().equals("RECONCILIATION"))
			report_sting += getTreeBodyHeader("USER: " + policy.getCreator(),"user");
		report_sting += getTreeBodyHeader("POLICY: " + policy.getName(),"policy");	
		for (GenericRule rule : policy.getRuleSet()) {
			String hspls = " [ derived from ";
			int i = 0;
			for(HSPL h:rule.getHSPLs()){
				hspls += h.getHSPLId();
				if(i+1<rule.getHSPLs().size()){
					hspls += ", ";
				}
				i++;
			}
			hspls +="]";
			report_sting += getTreeBodyHeader("RULE: " + rule.getName() + hspls,"rule");
			for(String s:rule.getConditionClause().getSelectorsNames()){
				report_sting += getTreeNode(s+": "+rule.getConditionClause().get(s).toSimpleString(),"none");
			}
			
			
			report_sting += getTreeNode("ACTION: "+rule.getAction(), "none");
			report_sting += getTreeBodyFooter();
		}
		report_sting += getTreeNode("DEFAULT ACTION: "+policy.getDefaultAction(), "rule");
		if(!policy.getCreator().equals("RECONCILIATION"))
			report_sting += getTreeBodyFooter();
		report_sting += getTreeBodyFooter();
		return report_sting;
	}
	
	/**
	 * Gets the HSPL tree.
	 *
	 * @param anomalies the anomalies
	 * @param rec_policy the rec_policy
	 * @param HSPLs the HSP ls
	 * @param type the type
	 * @return the HSPL tree
	 * @throws InvalidActionException the invalid action exception
	 * @throws NoExternalDataException the no external data exception
	 */
	private static String getHSPLTree(Collection<PolicyAnomaly> anomalies, LinkedList<Policy> rec_policy, HashSet<String> HSPLs, String type) throws InvalidActionException, NoExternalDataException {
		HashMap<String,HashSet<HSPL>> hspl = new HashMap<>();
		if(rec_policy!=null  && (type.equals("REC") || type.equals("MUCA"))){			
			hspl.put("DEFAULT", new HashSet<HSPL>());
			for(Policy policy:rec_policy){
				
				for(GenericRule rule:policy.getRuleSet()){
					for (PolicyAnomaly anomaly : anomalies) {
						if (anomaly.getConflict().equals(ConflictType.INCONSISTENT)){
							HashMap<String, HSPL> hh = new HashMap<>();
							boolean found = false;
							for(GenericRule r:anomaly.getRule_set()){
								if(!r.getName().equals(rule.getName())){
									for(HSPL h:rule.getHSPLs()){
										if(!HSPLs.contains(h.getHSPLId())){
											if(!hh.containsKey(h.getHSPLId()))
												hh.put(h.getHSPLId(), h);
										}
									}
								} 
							}
							for(GenericRule r:anomaly.getRule_set()){
								if(r.getName().equals(rule.getName())){
									found = true;
									for(HSPL h:rule.getHSPLs()){
										if(HSPLs.contains(h)){
											if(!hspl.containsKey(h.getHSPLId())){
												hspl.put(h.getHSPLId(), new HashSet<HSPL>());
											} 
											for(HSPL hhh:hspl.get(h.getHSPLId())){
												if(!hh.containsKey(hhh.getHSPLId()))
													hh.put(hhh.getHSPLId(), hhh);
											}
											hspl.get(h.getHSPLId()).clear();
											hspl.get(h.getHSPLId()).addAll(hh.values());
										}
									}
								} 
							}
							if(!found){
								for(HSPL hhh:hspl.get("DEFAULT")){
									if(!hh.containsKey(hhh.getHSPLId()))
										hh.put(hhh.getHSPLId(), hhh);
								}
								hspl.get("DEFAULT").clear();
								hspl.get("DEFAULT").addAll(hh.values());
							}
						}
					}
				}
				
				
			}
			
		}
		
		
		String report_sting = getTreeHeader("treeview4","Summary of the impact of reconciliation on HSPL statements", "rootfolder");
		HSPLs.add("DEFAULT");
		for (String  h : HSPLs) {
			if(h.equals("DEFAULT"))
				report_sting += getTreeBodyHeader("Default HSPL rule (ALLOW all)","policy");
			else
				report_sting += getTreeBodyHeader(h,"policy");
			if(!hspl.keySet().contains(h) || hspl.get(h).size()==0){
				report_sting += getTreeNode("No changes from reconciliation" ,"none");
			} else {
				for (HSPL hh : hspl.get(h)) {
					report_sting += getTreeBodyHeader(hh.getHSPLId(), "rule");
					report_sting += getTreeNode(hh.getHSPLText(), "none");
					report_sting += getTreeBodyFooter();
				}
			}
			report_sting += getTreeBodyFooter();
			
		}
		report_sting += getTreeFooter();
		return report_sting;
	}



	/**
	 * Gets the conflict tree.
	 *
	 * @param anomalies the anomalies
	 * @param rec_policy the rec_policy
	 * @param type the type
	 * @return the conflict tree
	 * @throws InvalidActionException the invalid action exception
	 * @throws NoExternalDataException the no external data exception
	 */
	private static String getConflictTree(Collection<PolicyAnomaly> anomalies, LinkedList<Policy> rec_policy, String type) throws InvalidActionException, NoExternalDataException {
		String report_sting = "";
		if(type.equals("SUCAS") || type.equals("SUCAD"))
			report_sting = getTreeHeader("treeview1","Anomalies", "rootfolder");
		if(type.equals("MUCA"))
			report_sting = getTreeHeader("treeview1","Conflicts", "rootfolder");
		if(type.equals("REC_C"))
			report_sting = getTreeHeader("treeview1","Summary of changes to the user MSPL policies by higher priority cooperative MSPL policies", "rootfolder");
		if(type.equals("REC_UC"))
			report_sting = getTreeHeader("treeview1","Summary of changes to the user MSPL policies by higher priority non-cooperative MSPL policies", "rootfolder");
		
		for (PolicyAnomaly anomaly : anomalies) {
			if (anomaly.getConflict().equals(ConflictType.INCONSISTENT) && (type.equals("REC_C") || type.equals("REC_UC") || type.equals("MUCA"))){
				
				GenericRule rule = anomaly.getRule_set()[0];
				if(rule.getName().contains("POLICY") && type.equals("REC_UC") || !rule.getName().contains("POLICY") && type.equals("REC_C") || type.equals("MUCA")){
					if(rule.getName().contains("POLICY"))
						report_sting +=  getTreeBodyHeader(rule.getName(),"policy");
					else
						report_sting +=  getTreeBodyHeader("RULE: " +rule.getName(),"rule");
					
					for(String s:rule.getConditionClause().getSelectorsNames()){						
						report_sting += getTreeNode(s+": "+rule.getConditionClause().get(s).toSimpleString(),"none");
					}
					report_sting += getTreeNode("ACTION: "+rule.getAction(), "none");
	//				
					report_sting += getTreeBodyHeader("MODIFIES THE FOLLOWING RULES","info");
					if(anomaly.getRule_set().length==1){
						report_sting += getTreeNode("DEFAULT ACTION OF USER POLICY","none");
					}
					for (GenericRule r : Arrays.copyOfRange(anomaly.getRule_set(), 1, anomaly.getRule_set().length)	) {
						report_sting += getTreeBodyHeader(r.getName(),"rule");
						report_sting += getTreeNode("ACTION: "+rule.getAction(), "none");
						for(String s:r.getConditionClause().getSelectorsNames()){						
							report_sting += getTreeNode(s+": "+r.getConditionClause().get(s).toSimpleString(),"none");
						}
						report_sting += getTreeBodyFooter();
					}
					report_sting += getTreeBodyFooter();
					report_sting += getTreeBodyFooter();
				}
			}
			if (type.equals("SUCAS") || type.equals("SUCAD") ){
				report_sting += getTreeBodyHeader(anomaly.getConflict().toString(),"pdf");
				
				GenericRule composed_Rule = anomaly.getRule_set()[0];
				if (type.equals("SUCAS") && anomaly.getConflict() != ConflictType.n_REDUNDANT && anomaly.getConflict() != ConflictType.n_SHADOWED) {
					Policy p =null;
					for(Policy pp:anomaly.getPolicyList()){
						if(pp.containsRule(anomaly.getRule_set()[0]))
							p=pp;
					}
					composed_Rule = p.getResolutionStrategy().composeRules(	anomaly.getRule_set());
				}
				
				report_sting += getTreeBodyHeader("RESULTING" + " (" + composed_Rule.getAction()+ ") ","html");
				
				String report_sting_temp = "";
				for(String s:composed_Rule.getConditionClause().getSelectorsNames()){
					Selector sel = composed_Rule.getConditionClause().get(s);
					boolean found = true;
					for (GenericRule rule : anomaly.getRule_set()) {
						if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
							found = false;
						}
					}

					if (found)
						report_sting_temp += getTreeNode(s+" : "+composed_Rule.getConditionClause().get(s).toSimpleString(),"none");
				}
				
				if(!report_sting_temp.equals("")){
					report_sting += getTreeBodyHeader("UNION ","none");
					report_sting += report_sting_temp;
					report_sting += getTreeBodyFooter();
				}
				
				report_sting_temp="";
				for(String s:composed_Rule.getConditionClause().getSelectorsNames()){
					Selector sel = composed_Rule.getConditionClause().get(s);
					boolean found = true;
					for (GenericRule rule : anomaly.getRule_set()) {
						if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
							found = false;
						}
					}

					if (!found)
						report_sting_temp += getTreeNode(s+" : "+composed_Rule.getConditionClause().get(s).toSimpleString(),"none");
				}
				
				if(!report_sting_temp.equals("")){
					report_sting += getTreeBodyHeader("AREA OF INTERSECTION ","none");
					report_sting += report_sting_temp;
					report_sting += getTreeBodyFooter();
				}
				
				report_sting += getTreeBodyFooter();
				
				for (GenericRule rule : anomaly.getRule_set()) {
					Policy p =null;
					for(Policy pp:anomaly.getPolicyList()){
						if(pp.containsRule(rule)){
							p=pp;
						}
					}
					String node_string = "RULE: "+rule.getName() + " (from policy: " +p.getName();
					
					if(p.getResolutionStrategy() instanceof FMRResolutionStrategy){
						FMRResolutionStrategy fmrres = (FMRResolutionStrategy)p.getResolutionStrategy();
						node_string +=  ", priority = " + fmrres.getExternalData(rule);
					}
					
					node_string += ", enforce action "+ rule.getAction()+ ") ";
					
					report_sting += getTreeBodyHeader(node_string,"rule");
					for(String s:rule.getConditionClause().getSelectorsNames()){
						
						report_sting += getTreeNode(s+" : "+rule.getConditionClause().get(s).toSimpleString(),"none");
					}
					report_sting += getTreeBodyFooter();
				}
				report_sting += getTreeBodyFooter();
			}
			
		}
		report_sting += getTreeFooter();
		return report_sting;
	}
	
	/**
	 * Gets the header.
	 *
	 * @return the header
	 */
	private static String getHeader(){
		String header = "";
		header += "<!DOCTYPE html>\n";
		header += "<html>\n";
		header += "<head>\n";
		header += "<title></title>\n";
		header += "<style rel=\"stylesheet\">\n";
		header += "img { border: none; }\n";
		header += "p { 	font-size: 1em; 	margin: 0 0 1em 0; }\n";
		header += "html { font-size: 100%;}\n";
		header += "body { font-size: 1em;}\n";
		header += "table { font-size: 100%;}\n";
		header += "input, select, textarea, th, td { font-size: 1em; }\n";
		header += "ol.tree { 	padding: 0 0 0 30px; 	width: 90%; }\n";
		header += "li { 	position: relative; 	margin-left: -15px; 	list-style: none; }\n";
		header += "li.file{ 	margin-left: -1px !important; }\n";
		header += "li.file span { color: #000; 	padding-left: 21px; 	text-decoration: none; 	display: block; 	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAYdJREFUeNqMksFqwkAQhmc3W4q0OSq09170LdJzb32IvkQVpIeeS6Gehdz6AkUoePOYe71VEBGiVkUxyaYzY9bENIYuTDbZ3f/b+Wci7ptNoCGEuMPpCsrHp9Z6qKMI4jjmBWVecL7utlqdHW4GFFpDhHtm3/M86PZ6D3QXxpchSqIlITSJgoBjt93CZr2G1WoFy+WS5/d2u4PnblF3YwAqQnEyBKElPs8sK006DCFEsO/78Oq64NTrby+u+4g7TwzQKUCSWDIG/kAcx2E7tm3Dh+fNDhmE2QwygCIIZcKvaDe1gBt5C9mRh9AlqCkE7C1ICZDcVASx9gCZWsgADhmUQCycwxMArgHXYZ9PIcTC9fDIAvY8nwHJTkHYQhCcsEAZYKvKIIJrmbGwGI/holo96oIugdC6sbCeTkEO+33wRyP6bVVSCD5kYOabumPW6SxpSEsXVL4Hg9piNjvPVPMgoKJRKCygUoq7QGdJQ1q6tYJR+5lM5peNxjP8Y+jNZk4aKsevAAMAmFzedjV8x2YAAAAASUVORK5CYII=) 0 0 no-repeat; }\n";
		header += "li.file span.rule{ background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAYFBMVEX///9XX23+/v6an6fCxcjz8/Ps7Ozw8PBqcX3g4eJobnj29vaSl5+kqLDV19nb3N7MztGFiZF/hIzR0dGKjpasr7WAhIx0eoa2ur+UmaJeZXN+hY/S0tLW2Ny+wMXIys4iw/SvAAAAhklEQVQYlVXP6w7CIAwFYAqj0Ml1Y27ilPd/SzEZiOff+dImLWOMCwDzYj0cQMq38YOYKsejVZutjKAU8AsyamH/QSYgxA57kEohuae44JjLt5epyW2bAfRU04XOdalSQmxbjGOVcLokqEvUwXnahpm4eyKE3/14N0Rgho9oyZAkGwRXX/sHF20F70y0+eMAAAAASUVORK5CYII=) 0 0 no-repeat; }\n";
		header += "li.file span.none { background: none; }\n";
		header += "li label { 	cursor: pointer; 	display: block; 	padding-left: 37px; 	background: url(data:image/png;base64,R0lGODlhEAAOALMAAOazToeHh0tLS/7LZv/0jvb29t/f3//Ub//ge8WSLf/rhf/3kdbW1mxsbP//mf///yH5BAAAAAAALAAAAAAQAA4AAARe8L1Ekyky67QZ1hLnjM5UUde0ECwLJoExKcppV0aCcGCmTIHEIUEqjgaORCMxIC6e0CcguWw6aFjsVMkkIr7g77ZKPJjPZqIyd7sJAgVGoEGv2xsBxqNgYPj/gAwXEQA7) 15px 1px no-repeat; }\n";
		header += "li label.rootfolder{ background: none; 	padding-left: 21px; }\n";
		header += "li label.policy{ background: url(data:image/png;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAQECAQEBAgICAgICAgICAQICAgICAgICAgL/2wBDAQEBAQEBAQEBAQECAQEBAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgL/wAARCAAUABQDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD+sX4pfH/wr8APFv7MMnxP8MeG1+DvxsstD+GmpeOZfh3ca/eaB8b/ABXDpt54MufGvjY3f2HwZ4FvIl1G0DXtszNd38UkM9vp+nag0Pc/Gb9oHwN8DvDPjfx14j/Zu1HxV4H8BSzRa1rngC8/Z21DVA8baPbW9tF4O8X/ABI0PUptYutW8RaBY2WmQxT6neXmuWUNvaSNeWnn0vjn8M9J+N37L2ofCXxF4LX4h+FfGvgrwbpni3wdFq0eg61q2gWdtpOqyzeDtYuHSDT/AB1Z6pp2lX2kyTz2cf2nTgovbWYxSj5h+CV/cftC/EHwf4UvNTu/Fnwy/ZH1zSvE/wARNfvPDHi/wjbfEv8AansLaWD4T6BqvhTx14v1S/sb74bfD86PrGvxsfsGofEXWtM1e3t9JufDv9mqN5G8lwM6EMRTzqFSusVzzjPD1KTVB4WpQVlUpVE/bU61JqdNqFKrCalOpCODr5rVx9WOJ+rf2VRoUIYb2VJUq8ZxlWddYhxXLX5r0pU68n7WzlSmnCnSZ9O/FPXJ7DW9IGm+Hv8AhCPtfhnSr6/8MSW2greaNqd1JeSXem6mvh+/vdOGrWx2W10dPvLuxaezd7a6uomW5lKx/jPMr+LojyANHtVAIPAF3fkY68c0V8xUqS9pNxTSv0bt0/yO+yVtOi/JGNrnjbxP4c1E6LpmrTx6fYWOmxWkUixyGCD7FD5VurBBujjj2opOXKoN7O2WOUfil43OR/bD4LM5xFGNzsFDO2F+ZyEQEnkhACeBRRXPOUlUklJpJ9/NG6SstDo9Oso/FNjba1r0lxf39ysqtK8zRiOKK4mRIY1h24jBDN825t0jfNt2qCiiuyjGMqcG4pt90u6OeTfNLXr/AJH/2Q==) 15px 1px no-repeat; }\n";
		header += "li label.rule{ background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAYFBMVEX///9XX23+/v6an6fCxcjz8/Ps7Ozw8PBqcX3g4eJobnj29vaSl5+kqLDV19nb3N7MztGFiZF/hIzR0dGKjpasr7WAhIx0eoa2ur+UmaJeZXN+hY/S0tLW2Ny+wMXIys4iw/SvAAAAhklEQVQYlVXP6w7CIAwFYAqj0Ml1Y27ilPd/SzEZiOff+dImLWOMCwDzYj0cQMq38YOYKsejVZutjKAU8AsyamH/QSYgxA57kEohuae44JjLt5epyW2bAfRU04XOdalSQmxbjGOVcLokqEvUwXnahpm4eyKE3/14N0Rgho9oyZAkGwRXX/sHF20F70y0+eMAAAAASUVORK5CYII=) 15px 1px no-repeat; }\n";
		header += "li label.user{ background: url(data:image/gif;base64,R0lGODlhEAAQAMQfAFWApnCexR4xU1SApaJ3SlB5oSg9ZrOVcy1HcURok/Lo3iM2XO/i1lJ8o2eVu011ncmbdSc8Zc6lg4212DZTgC5Hcmh3f8OUaDhWg7F2RYlhMunXxqrQ8n6s1f///////yH5BAEAAB8ALAAAAAAQABAAAAVz4CeOXumNKOpprHampAZltAt/q0Tvdrpmm+Am01MRGJpgkvBSXRSHYPTSJFkuws0FU8UBOJiLeAtuer6dDmaN6Uw4iNeZk653HIFORD7gFOhpARwGHQJ8foAdgoSGJA1/HJGRC40qHg8JGBQVe10kJiUpIQA7) 15px 1px no-repeat; }\n";
		header += "li label.info{ background: url(data:image/gif;base64,R0lGODlhDwAOAPcAAAA5vWtjSnNKAIxrGJy1/6WMQqWMSqW1/6W9/629/63G/7WUSrWcSrXG/72cMb2lUr3O/8bW/861a87e/9a1Utbe/961Qt61St7n/+fGa+fv/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////yH5BAEAABsALAAAAAAPAA4AAAhmADcIHEiw4EAACAEYJAiAgAIIBBQubBghQoUJByQWBNDAIgYMETQyhFABgwYNFUQeJDDBpAYFKg8isJgAgAAJCzckBBCgwIUMOQcKGMDAAoWgAocucGAA6YahDwYIcDpUwFSqVwMCADs=) 15px 1px no-repeat; }\n";
		header += "li label.capability{ background: url(data:image/jpg;base64,/9j/4AAQSkZJRgABAQEBLAEsAAD/7QBEUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAACgcAnQAHChjKSBGdXJ0YWV2IHwgRHJlYW1zdGltZS5jb20cAgAAAgAE/+EBEEV4aWYAAE1NACoAAAAIAAYBGgAFAAAAAQAAAFYBGwAFAAAAAQAAAF4BKAADAAAAAQACAAACEwADAAAAAQABAACCmAACAAAAHQAAAGacmwABAAAAhAAAAIQAAAAAAAABLAAAAAEAAAEsAAAAAShjKSBGdXJ0YWV2IHwgRHJlYW1zdGltZS5jb20AAGgAdAB0AHAAOgAvAC8AdwB3AHcALgBkAHIAZQBhAG0AcwB0AGkAbQBlAC4AYwBvAG0ALwByAG8AeQBhAGwAdAB5AC0AZgByAGUAZQAtAHMAdABvAGMAawAtAGkAbQBhAGcAZQBzAC0AaQBtAGEAZwBlADMANQA3ADQAMAA0ADgAOQAAAP/bAEMACwgICggHCwoJCg0MCw0RHBIRDw8RIhkaFBwpJCsqKCQnJy0yQDctMD0wJyc4TDk9Q0VISUgrNk9VTkZUQEdIRf/bAEMBDA0NEQ8RIRISIUUuJy5FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRf/AABEIABQAFAMBEQACEQEDEQH/xAAYAAADAQEAAAAAAAAAAAAAAAACBAUGB//EACcQAAIBAwIFBAMAAAAAAAAAAAECAwQREgAFEyFRYXEUMUGBBiIk/8QAGQEAAwEBAQAAAAAAAAAAAAAAAQMEAAIF/8QAHhEAAQQDAQEBAAAAAAAAAAAAAQACAxEEEiFhQVH/2gAMAwEAAhEDEQA/AOoV1etGEIBkkYlVjHIsbe9z7AddTz5DIW7uPAu2sLjQS1LupedIZ4uCXJxYPmrHmbXsLH6+NTY2dHOdW2D6mSRFnSqBGZyDEDxq+76EgilH/JYZDS+oEuHCRwzKbFFNv2+iBfsTqDOgMrBXSDdfoTo3alSdi/vr8o5pGiiaN24kmWBsSAO5PLwvfUOFivbKJHiqv5Vk8CbI8FtBbANiLMRftr3hddUp8QVdJDW00lPUJnFKuLC9rjzooJTatkpdpWT0/EdpSMnka5IF7Dp8nWWQV7kVJA6DUk0zmOoIEr//2Q==) 15px 1px no-repeat; }\n";
		header += "li input { 	position: absolute; 	left: 0; 	margin-left: 0; 	opacity: 0; 	z-index: 2; 	cursor: pointer; 	height: 1em; 	width: 1em; 	top: 0; }\n";
		header += "li input + ol { 	margin: -0.938em 0 0 -44px;  height: 1em; 	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAURJREFUeNpi/P//PwMlgImBQkCxASwwRlLLKwYmJqZgRkbGbiBXEYva+0Dvlv7792/tvBoxTAO+fv0MororE6UU9VU5MHRfvP1DsX3+M5DhaxkYxDC98ObNGxBW1FVmY/j16xcYu6SdYvjw4QPDixcvGGSEvoLlQeqweuHdu7dg+vfv32D85ctXsNijR4/B4hwcnHA1WA348uUbmP779y+DUchOuIKQsltgetsUE7garAb8/w9h/vz5h+H0Sk8w2yRsN8OZVa5g9ocPn+BqsBrAzs4PdQEzw48ff+Fi375B2Gxs3HA1WNPB45NlDNzcIvfPXv8LVMwJxmdWOcDZF2//A8uD1GF1wefXZ8Q+Pt42oWN+VBED41d5DKv+/30IlJ8IVCcF5D2DCTPC8gIwAXEDKT4Qk0Di+wzU8xnDgKGbmQACDAAtTZadqmiADQAAAABJRU5ErkJggg==) 40px 0 no-repeat; }\n";
		header += "li input + ol > li { 	display: none; 	margin-left: -14px !important; 	padding-left: 1px; }\n";
		header += "li input:checked + ol { margin: -1.25em 0 0 -44px;  padding: 1.563em 0 0 80px; height: auto; 	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAASxJREFUeNpi/P//PwMlgImBQkCxASwwRlLLKwYmJqZgRkbGbiBXEYva+0Dvlv7792/tvBoxTAO+fv0MororE6UU9VU5MHRfvP1DsX3+M5DhaxkYsBjw5s0bEKWoq6zA8OvXL7AYKIC/f//O8OPHDwYZIVaQGqjLlDENePfuLZj+/fs3GH/58pXh/fv3YDYIcHBwwtVgDYMvX76B6b9//zIYhezEULhtiglcDVYD/v+HMH/+/MNweqUnhsIPHz7B1WA1gJ2dH+oCZqCf/2IoZGPjhqvBmg4enyxj4OYWuX/2+l+gYk4MfPH2P7A8SB1WF3x+fUbs4+NtEzrmRxUxMH6Vx7Dq/9+HQPmJQHVSQN4zmDAjLC8AExA3kOIDMQkkvs9APZ8xDBi6mQkgwADDMYZH9Ls66AAAAABJRU5ErkJggg==) 40px 5px no-repeat; }\n";
		header += "li input:checked + ol > li {   display: block;   margin: 0 0 0.125em; }\n";
		header += "li input:checked + ol > li:last-child {   margin: 0 0 0.063em; }\n";
		header += "</style>";
		header += "</head>\n";
		header += "<body>\n";
		return header;
	}
	
	/**
	 * Gets the policy info header.
	 *
	 * @return the policy info header
	 */
	private static String getPolicyInfoHeader(){
		String header = "";
		header += "<div style=\"float:top; margin:10px\">\n";
		return header;
	}
	
	/**
	 * Gets the policy info body.
	 *
	 * @param num_p the num_p
	 * @param num_r the num_r
	 * @param num_a the num_a
	 * @param num_ra the num_ra
	 * @param coop the coop
	 * @param non_coop the non_coop
	 * @return the policy info body
	 */
	private static String getPolicyInfoBody(int num_p, int num_r, int num_a, int num_ra, List<String> coop, List<String> non_coop){
		String header = "";
		int i=0;
		header = "<FONT SIZE=+1>\n";
		header += "<B>Number of input policies </B>: "+num_p+"</br>\n";
//		header += "<B>Number of rules analysed </B>: "+num_r+"</br>\n";
		header += "<B>Number of reconcilied rules </B>: "+num_a+"</br>\n";
		header += "<B>Modifications introduced by other actors </B>: "+num_ra+"</br>\n";
		if(coop!=null && non_coop!=null)
			header += "<B>Number of policy stack layers </B>: "+(coop.size()+non_coop.size())+"</br>\n";
		if(coop!=null)
			header += "<B>Number of policy stack layers </B>: "+(coop.size())+"</br>\n";
		if(coop!=null){
			header += "<B>Cooperative policy stack </B>: \n";
			i=0;
			for(String s:coop){
				header += s;
				if (i+1< coop.size()){
					header += ",  \n";
				}
				i++;
			}
		}
		if(non_coop!=null){
			header += "</br><B>Non-Cooperative policy stack </B>: \n";
			i=0;
			for(String s:non_coop){
				header += s;
				if (i+1< non_coop.size()){
					header += ",  \n";
				}
				i++;
			}
		}
		header +="</FONT>\n";
		return header;
	}
	
	/**
	 * Gets the policy info footer.
	 *
	 * @return the policy info footer
	 */
	private static String getPolicyInfoFooter(){
		String header = "";
		header = "</div>\n";
		return header;
	}
	
	/**
	 * Gets the tree header.
	 *
	 * @param id the id
	 * @param text the text
	 * @param image the image
	 * @return the tree header
	 */
	private static String getTreeHeader(String id, String text, String image){
		String header = "";
		header += "<div>\n";
		header += "<ol class=\"tree\">\n";
		header += "<li>\n";
		header += "<label class=\""+image+"\" for=\""+text.hashCode()+"\">"+text+"</label> <input type=\"checkbox\" checked id=\""+text.hashCode()+"\" />\n";
		header += "<ol>\n";
		return header;
	}
	
	/**
	 * Gets the tree body header.
	 *
	 * @param text the text
	 * @param image the image
	 * @return the tree body header
	 */
	private static String getTreeBodyHeader(String text, String image){
		String header = "";
		String id = "" + text.hashCode()+Math.random();
		header += "<li>\n";
		header += "<label class=\""+image+"\"  for=\""+id+"\">"+text+"</label> <input type=\"checkbox\" id=\""+id+"\" />\n";
		header += "<ol>\n";
		return header;
	}
	
	/**
	 * Gets the tree node.
	 *
	 * @param text the text
	 * @param image the image
	 * @return the tree node
	 */
	private static String getTreeNode(String text, String image){
		String header = "";
		header += "<li class=\"file\">\n";
		header += "<span class=\""+image+"\">"+text+"</span>\n";
		header += "</li>\n";
		return header;
	}
	
	/**
	 * Gets the tree body footer.
	 *
	 * @return the tree body footer
	 */
	private static String getTreeBodyFooter(){
		String header = "";
		header += "</ol>\n";
		header += "</li>\n";
		return header;
	}
		
	/**
	 * Gets the tree footer.
	 *
	 * @return the tree footer
	 */
	private static String getTreeFooter(){
		String header = "";
		header += "</ol>\n";
		header += "</li>\n";
		header += "</ol>\n";
		header += "</div>\n";
		return header;
	}
	
	/**
	 * Gets the footer.
	 *
	 * @return the footer
	 */
	private static String getFooter(){
		String header = "";
		header += "</body>\n";
		header += "</html> \n";
		
		return header;
	}
}
