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

public class SingleUserConflictAnalysis {

	public static void main(String[] args) throws Exception {

		String report_sting = "";
		String report = "report.txt";

		if (args.length == 0) {
			report_sting += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
			report_sting += "Single Analysis\n";
			report_sting += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n";
			report_sting += singleAnalysis("iptables.xml");
			report_sting += "\n\n\n\n";
			report_sting += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
			report_sting += "Distributed Analysis\n";
			report_sting += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n";
			String[] filenames = { "iptables1.xml", "iptables2.xml" };
			report_sting += distributedAnalysis(filenames);
		}

		if (args.length == 2) {
			String filename = args[1];
			report = args[0];
			report_sting = singleAnalysis(filename);
		}

		if (args.length > 2) {
			report = args[0];
			report_sting = distributedAnalysis(Arrays.copyOfRange(args, 2,
					args.length));
		}

		System.out.println(report_sting);

		File logFile = new File(report);

		BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
		writer.write(report_sting);

		// Close writer
		writer.close();

	}

	private static String singleAnalysis(String filename) throws Exception {

		File file = new File(filename);

		Policy policy = PolicyWrapper.getFilteringPolicy(file);

		SelectorTypes selectorTypes = PolicyWrapper.getFilteringSelectorTypes();

		Analyzer analyzer = new Analyzer();
		Set<PolicyAnomaly> anomalies = analyzer.getSingleAnomalies(policy,
				selectorTypes);
		HashSet<GenericRule> rule_anomalies = new HashSet<>();
		for (PolicyAnomaly anomaly : anomalies) {
			for (GenericRule rule : anomaly.getRule_set()) {
				rule_anomalies.add(rule);
			}
		}
		String report_sting = "###############################################\n";
		report_sting += "#                                             #\n";
		report_sting += "#    Number of rules analysed      : "
				+ policy.getRuleSet().size() + "\t      #\n";
		report_sting += "#    Number of anomalys found      : "
				+ anomalies.size() + "\t      #\n";
		report_sting += "#    Number of rules with anomalys : "
				+ rule_anomalies.size() + "\t      #\n";
		report_sting += "#                                             #\n";
		report_sting += "###############################################\n";
		for (PolicyAnomaly anomaly : anomalies) {
			report_sting += "\n===============================================\n";
			report_sting += anomaly.getConflict();
			report_sting += " :\n";
			for (GenericRule rule : anomaly.getRule_set()) {
				report_sting += rule.getName() + "(" + rule.getAction();
				if(policy.getResolutionStrategy() instanceof FMRResolutionStrategy){
					FMRResolutionStrategy fmrres = (FMRResolutionStrategy)policy.getResolutionStrategy();
					report_sting +=  ", " + fmrres.getExternalData(rule);
				}
				report_sting += ") ";
			}

			GenericRule composed_Rule = anomaly.getRule_set()[0];
			if (anomaly.getConflict() != ConflictType.n_REDUNDANT
					&& anomaly.getConflict() != ConflictType.n_SHADOWED) {
				composed_Rule = policy.getResolutionStrategy().composeRules(
						anomaly.getRule_set());
			}
			report_sting += "==>  " + composed_Rule.getAction();
			report_sting += "\n";
			String selectors = ". . . . . . . . . . . . . . . . .\n";
			for (String s : composed_Rule.getConditionClause().getSelectorsNames()) {
				Selector sel = composed_Rule.getConditionClause().get(s);
				boolean found = true;
				for (GenericRule rule : anomaly.getRule_set()) {
					if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
						found = false;
					}
				}

				if (found)
					selectors = selectors + s + " : " + sel.toString() + "\n";
				else
					selectors = s + " : " + sel.toString() + "\n" + selectors;
			}
			report_sting += selectors;
			report_sting += "\n";
			report_sting += "-----------------------------------------------\n";

			for (GenericRule rule : anomaly.getRule_set()) {
				report_sting += rule + "\n\n";

			}
		}

		return report_sting;
	}

	private static String distributedAnalysis(String[] filenames)
			throws Exception {

		LinkedList<LinkedList<Policy>> policy_list = new LinkedList<LinkedList<Policy>>();
		LinkedList<Policy> p_list = new LinkedList<Policy>();
		for (String fname : filenames) {
			File file = new File(fname);
			Policy p = PolicyWrapper.getFilteringPolicy(file);

			p_list.add(p);
		}
		policy_list.add(p_list);

		ComposedPolicy policy = new ComposedPolicy(policy_list,
				PolicyType.FILTERING, "ComposedPolicy");

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

		HashSet<GenericRule> rule_anomalies = new HashSet<>();
		for (PolicyAnomaly anomaly : anomalies) {
			for (GenericRule rule : anomaly.getRule_set()) {
				rule_anomalies.add(rule);
			}
		}
		String report_sting = "###############################################\n";
		report_sting += "#                                             #\n";
		report_sting += "#    Number of policies analysed   : "
				+ policy.getOriginalPolicy().size() + "\t      #\n";
		report_sting += "#    Number of rules analysed      : "
				+ policy.getRuleSet().size() + "\t      #\n";
		report_sting += "#    Number of anomalys found      : "
				+ anomalies.size() + "\t      #\n";
		report_sting += "#    Number of rules with anomalys : "
				+ rule_anomalies.size() + "\t      #\n";
		report_sting += "#                                             #\n";		
		for(Policy p:policy.getOriginalPolicy()){
			report_sting += "#  .........................................  #\n";
			report_sting += "#    Name \t\t: "+ p.getName() +"\t      #\n";
			report_sting += "#    DefaultAction \t: "+ p.getDefaultAction() +"\t\t      #\n";
			report_sting += "#    ResolutionStrategy : "+ p.getResolutionStrategy().toSimpleString() +"\t\t      #\n";
			report_sting += "#    RuleNumber \t: "+ p.getRuleSet().size() +"\t\t      #\n";
		}
		report_sting += "#                                             #\n";
		report_sting += "###############################################\n";
		for (PolicyAnomaly anomaly : anomalies) {
			report_sting += "\n===============================================\n";
			report_sting += anomaly.getConflict();
			report_sting += " :\n";
			for (GenericRule rule : anomaly.getRule_set()) {
				report_sting += rule.getName() + "(" + rule.getAction();
				Policy p = null;
				for(Policy pp: p_list){
					if(pp.containsRule(rule)){
						p = pp;
					}
				}
				if(p.getResolutionStrategy() instanceof FMRResolutionStrategy){
					FMRResolutionStrategy fmrres = (FMRResolutionStrategy)p.getResolutionStrategy();
					report_sting +=  ", " + p.getName();
					report_sting +=  ", " + fmrres.getExternalData(rule);
				}
				report_sting += ") ";
			}

			GenericRule composed_Rule = anomaly.getRule_set()[0];
			report_sting += "==>  " + composed_Rule.getAction();
			report_sting += "\n";
			String selectors = ". . . . . . . . . . . . . . . . .\n";
			for (String s : composed_Rule.getConditionClause().getSelectorsNames()) {
				Selector sel = composed_Rule.getConditionClause().get(s);
				boolean found = true;
				for (GenericRule rule : anomaly.getRule_set()) {
					if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
						found = false;
					}
				}

				if (found)
					selectors = selectors + s + " : " + sel.toString() + "\n";
				else
					selectors = s + " : " + sel.toString() + "\n" + selectors;
			}
			report_sting += selectors;
			report_sting += "\n";
			report_sting += "-----------------------------------------------\n";

			for (GenericRule rule : anomaly.getRule_set()) {
				report_sting += rule + "\n\n";

			}
		}

		return report_sting;
	}
}

/*
 * 
 * tipo di conflitto breve descrizione del tipo di conflitto e dei problemi che
 * può causare
 * 
 * lista (selettori uguali, valore selettori uguali)
 * 
 * selettori diversi, lista di k elementi selettore diverso 1, r1 selettore
 * diverso 1, r2 selettore diverso 1 intersezione r1\cap r2 ... selettore
 * diverso k, r1 selettore diverso k, r2 selettore diverso k intersezione r1\cap
 * r2
 * 
 * selection condition ristretta ai selettori diversi r1 selection condition
 * ristretta ai selettori diversi r2 selection condition ristretta ai selettori
 * diversi r1 \cap r2 selection condition ristretta ai selettori diversi r1
 * \setminus r2 (se computabile, altrimenti split in rettangoli? Potrebbe essere
 * difficile)
 * 
 * selection condition ristretta ai selettori diversi r2 \setminus r1 (se
 * computabile, altrimenti split in rettangoli? Potrebbe essere difficile)
 * 
 * azione r1 azione r2 azione finale
 * 
 * regola intersezione (composition)
 * 
 * 
 * lista azioni di risoluzione: per ogni azione: (nome, descrizione,
 * conseguenze, cambiamenti nella policy)
 */
