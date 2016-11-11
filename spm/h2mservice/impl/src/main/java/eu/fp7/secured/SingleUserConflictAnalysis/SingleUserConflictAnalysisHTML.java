package eu.fp7.secured.SingleUserConflictAnalysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import javax.xml.bind.JAXBException;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.ComposedPolicy;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.policy.tools.Analyzer;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalForm;
import eu.fp7.secured.policy.translation.canonicalform.CanonicalFormGenerator;
import eu.fp7.secured.policy.translation.semilattice.SemiLatticeGenerator;
import eu.fp7.secured.policy.utils.PolicyType;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.utils.HTMLView;

public class SingleUserConflictAnalysisHTML {

	public static void main(String[] args) throws Exception {


		
		
		if (args.length == 2) {		
			System.out.println("Save report to : " + args[0]);
			System.out.println();
			Policy policy = PolicyWrapper.getFilteringPolicy(new File(args[1]));
			LinkedList<Policy> p_list = new LinkedList<Policy>();
			p_list.add(policy);
			System.out.println("Reading policy : " + args[1]);
			HTMLView.createHTMLView(args[0], singleAnalysis(policy), p_list, null,"SUCAS","Single User Conflict Analysis Report","Single User Conflict Analysis Staticstics");
		} else {
			Policy policy = PolicyWrapper.getFilteringPolicy(new File(""
					+ "../test/input/child_layer7-firewall.xml"));
			LinkedList<Policy> p_list = new LinkedList<Policy>();
			p_list.add(policy);
			
			HTMLView.createHTMLView("../test/report/singleUserReportSinglePolicy.html", singleAnalysis(policy), p_list, null,"SUCAS","Single User Conflict Analysis Report","Single User Conflict Analysis Staticstics");
			
		}


		
		System.out.println("Calculation completed");
		System.out.println("Open report now");

	}

	private static Set<PolicyAnomaly> singleAnalysis(Policy policy) throws Exception {

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		Analyzer analyzer = new Analyzer();
		Set<PolicyAnomaly> anomalies = analyzer.getSingleAnomalies(policy,
				selectorTypes);
		
		return anomalies;
	}


}


