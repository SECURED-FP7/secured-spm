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
package eu.fp7.secured.SingleUserConflictAnalysis;

import java.awt.geom.GeneralPath;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBException;

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
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.policy.tools.Analyzer;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalFormGenerator;
import eu.fp7.secured.policy.translation.semilattice.SemiLatticeGenerator;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.utils.HTMLView;
import eu.fp7.secured.utils.PolicyWrapper;

/**
 * The Class SingleUserConflictAnalysisHTML.
 */
public class SingleUserConflictAnalysisHTML {

	/**
	 * Analyse sp.
	 *
	 * @param policy the policy
	 * @return the string
	 * @throws Exception the exception
	 */
	public static String analyseSP(String policy) throws Exception{

		LinkedList<Policy> p_list = new LinkedList<>();
		HashSet<String> HSPLs = new HashSet<>();


		ITResource itr = PolicyWrapper.getITResource(new String(DatatypeConverter.parseBase64Binary(policy)));
		Policy p = PolicyWrapper.getPolicy(itr, "USER");
		p_list.add(p);
		for(GenericRule r:p.getRuleSet()){
			for(HSPL h:r.getHSPLs())
				HSPLs.add(h.getHSPLId());
		}
		
//		System.out.println(p.getDefaultAction());
//		for(GenericRule r:p.getRuleSet()){
//			System.out.println(r);
//		}
		

		Collection<PolicyAnomaly> anomalies = singleAnalysis(p);
		

		return new String(DatatypeConverter.printBase64Binary(HTMLView.createHTMLView(anomalies, null, null, HSPLs, p_list, null,"SUCAS","Single User Conflict Analysis Report","Single User Conflict Analysis Staticstics").getBytes()));
	}


	/**
	 * Analyse mp.
	 *
	 * @param policies the policies
	 * @return the string
	 * @throws Exception the exception
	 */
	public static String analyseMP(List<String> policies) throws Exception{
		LinkedList<Policy> p_list = new LinkedList<>();
		HashSet<String> HSPLs = new HashSet<>();

		for(String policy:policies){
			ITResource itr = PolicyWrapper.getITResource(new String(DatatypeConverter.parseBase64Binary(policy)));
			Policy p = PolicyWrapper.getPolicy(itr, "USER");
			p_list.add(p);

			for(GenericRule r:p.getRuleSet()){
				for(HSPL h:r.getHSPLs())
					HSPLs.add(h.getHSPLId());
			}
		}


		Collection<PolicyAnomaly> anomalies = distributedAnalysis(p_list);

		return new String(DatatypeConverter.printBase64Binary(HTMLView.createHTMLView(anomalies, null, null, HSPLs, p_list, null,"SUCAD","Single User Conflict Analysis Report","Single User Conflict Analysis Staticstics").getBytes()));
	}


	/**
	 * Single analysis.
	 *
	 * @param policy the policy
	 * @return the sets the
	 * @throws Exception the exception
	 */
	private static Set<PolicyAnomaly> singleAnalysis(Policy policy) throws Exception {

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		Analyzer analyzer = new Analyzer();
		Set<PolicyAnomaly> anomalies = analyzer.getSingleAnomalies(policy,
				selectorTypes);

		return anomalies;
	}

	/**
	 * Distributed analysis.
	 *
	 * @param p_list the p_list
	 * @return the sets the
	 * @throws Exception the exception
	 */
	private static Set<PolicyAnomaly> distributedAnalysis(LinkedList<Policy> p_list)
			throws Exception {

		LinkedList<LinkedList<Policy>> policy_list = new LinkedList<LinkedList<Policy>>();
		policy_list.add(p_list);

		ComposedPolicy policy = new ComposedPolicy(policy_list,new LinkedList<Capability>(), "ComposedPolicy", "USER");

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		Analyzer analyzer = new Analyzer();

		CanonicalFormGenerator can_gen = CanonicalFormGenerator.getInstance(
				policy, selectorTypes);
		can_gen.generateClosure();
		CanonicalForm can = can_gen.getCanonicalForm();
		SemiLatticeGenerator slgen = new SemiLatticeGenerator();
		slgen.generateSemilattice(can);

		Set<PolicyAnomaly> anomalies = analyzer.getDistributedAnomalies(policy,
				can, can.getSemiLattice());

		return anomalies;
	}
}


