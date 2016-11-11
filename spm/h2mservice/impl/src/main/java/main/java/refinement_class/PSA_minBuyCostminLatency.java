package main.java.refinement_class;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.moeaframework.Analyzer;
import org.moeaframework.Executor;
import org.moeaframework.core.NondominatedPopulation;
import org.moeaframework.core.Solution;
import org.moeaframework.core.variable.BinaryVariable;
import org.moeaframework.problem.AbstractProblem;

//import main.java.refinement_class.PSA_minBuyCostmaxRating.PSASelectionLatencyCost;

public class PSA_minBuyCostminLatency {


	// objectives (trade-off):
	// 1. minimize the latency to transfer (1Mb/s) of traffic for each HSPL
	// 2. minimize the economic cost of transferring this traffic (e.g., 0.1 euro for each Mb/s ), each PSA has a different cost
	//psa1 = impl1 + impl2 ...
	//...
	//psaN = impl1  + ... + impl2N
	// min fobj1: psa1Latency * psa1 + ... i.e., minize the latency of transferring traffic by using a particular psa
	// min fobj2: f[1] =
				// if(psa[0] > 0)
				//	 f[1] = f[1] + psa1Cost
				// if(psa[1] > 0)
				//f[1] = f[1] + psa2Cost
				// cost for buy a PSA

	public static class PSASelectionLatencyCost extends AbstractProblem {
		HashMap hspl_impls; // [0] -> [0, 1] i.e., hspl with id 0 has implementations with ids 0 and 1
							// [1] -> [2, 3]
		HashMap impls_psa;  // [0] -> [0, 1, 2] i.e., impl with id 0 uses psas with id 0,1,2
		HashMap psaLatency; // [0] -> [0.3]
		HashMap psaCost;    // [0] -> [1.0]
		int noVariable = 0;
		int noConstraints = 0;
		String temp;

		public PSASelectionLatencyCost(int noDecisionVariable, int noObjective, HashMap hspl_impls, HashMap impls_psa, HashMap psaLatency, HashMap psaCost) {
			super (noDecisionVariable,noObjective);
			this.hspl_impls = hspl_impls;
			this.impls_psa = impls_psa;
			this.psaLatency = psaLatency;
			this.psaCost = psaCost;
		}

		/*  // model
		// psa1
		psa[0] = 1 impls[0] + 1 impls[1]; // 1 Mb/s
		// psa2
		psa[1] = 1 impls[0];
		// psa3
		psa[2] = 1 impls[1];

		// constraint
		double[] c = new double[3];
		c[0] = 1.1 - impls[0] - impls[1];
		//c[1] = 1 - impls[1];
		//c[2] = 1 - impls[0];

		f[0] = psa1Perf * psa[0] + psa2Perf * psa[1] + psa3Perf * psa[2]; // latency
		f[1] =
		if(psa[0] > 0)
		f[1] = f[1] + psa1Cost
		if(psa[1] > 0)
		f[1] = f[1] + psa2Cost
		// cost for buy a PSA
		*/

		@Override
		public void evaluate(Solution solution) {

			int[] impls = new int[impls_psa.keySet().size()];
			for(int i=0; i<impls.length; i++){
				BinaryVariable binary = (BinaryVariable) solution.getVariable(i);
				if(binary.get(0)){
					impls[i] = 1;
				} else {
					impls[i] = 0;
				}
			}


			double[] psa = new double[psaLatency.keySet().size()]; // N psa

			// constraints
			double[] c = new double[hspl_impls.keySet().size()];

			// for each hspl we need to identify with implementations and psa are involved
			Iterator it = hspl_impls.keySet().iterator();
			while(it.hasNext()){
				String hsplid = (String) it.next();
				LinkedList implsIds = (LinkedList) hspl_impls.get(hsplid);
				// for each impl we need to identify which psa are involved and related constraints
				// constraint
				c[Integer.valueOf(hsplid)] = 1.1;
				Iterator it2 = implsIds.iterator();
				while(it2.hasNext()){
					String implId = (String) it2.next();
					LinkedList psaIds = (LinkedList) impls_psa.get(implId);
					// for each psa we build the equation
					Iterator it3 = psaIds.iterator();
					while(it3.hasNext()){
						String psaId = (String) it3.next();
						psa[Integer.valueOf(psaId)] = psa[Integer.valueOf(psaId)] + impls[Integer.valueOf(implId)]; // here we can add the quantity of traffic, e.g., 1Mb introduced by a hspl
					}
					c[Integer.valueOf(hsplid)] = c[Integer.valueOf(hsplid)] - impls[Integer.valueOf(implId)];
				}
			}

			// fobj
			double[] f = new double[2]; // number of objectives
			// fobj1
			// for each psa we derive the latency performance
			it = psaLatency.keySet().iterator();
			while(it.hasNext()){
				String psaId = (String) it.next();
				f[0] = f[0] + Double.valueOf((String)psaLatency.get(psaId)) * psa[Integer.valueOf(psaId)];
			}

			// fobj2
			// for each psa we derive the latency performance
			it = psaCost.keySet().iterator();
			while(it.hasNext()){
				String psaId = (String) it.next();
				if(psa[Integer.valueOf(psaId)] > 0)
				{
					f[1] = f[1] + Double.valueOf((String)psaCost.get(psaId));
				}
			}


			solution.setObjectives(f);
			solution.setConstraints(c);
		}

		@Override
		public Solution newSolution() {
			noVariable = impls_psa.keySet().size(); // the number of impls
			noConstraints = hspl_impls.keySet().size(); // the number of hspl
			Solution solution = new Solution(noVariable, 2, noConstraints); // 2variable, 2 objf, 3 constraints
			for(int i = 0; i< noVariable; i++){
				solution.setVariable(i, new BinaryVariable(1));
			}

			return solution;
		}


	}

	public static class OptWrapper {
		// external representation
		HashMap hspl_impls_ext = new HashMap();
		HashMap impls_psa_ext = new HashMap();
		HashMap psa_latency_ext = new HashMap();
		HashMap psa_cost_ext = new HashMap();


		// internal representation
		HashMap hspl_impls = new HashMap();
		HashMap impls_psa = new HashMap();
		HashMap psa_latency = new HashMap();
		HashMap psa_cost = new HashMap();

		// external vs internal mapping
		HashMap hspl_index = new HashMap();
		HashMap impls_index = new HashMap();
		HashMap psa_index = new HashMap();
		int hspl_i = 0;
		int impl_i = 0;
		int psa_i = 0;

		int noVariable;

		// optimization results
		NondominatedPopulation optResult = null;

		public OptWrapper(){

		}

		public void loadExternalRepresentation(HashMap hspl_impls_ext_input, HashMap impls_psa_ext_input, HashMap psa_latency_ext_input, HashMap psa_cost_ext_input ){
			hspl_impls_ext=hspl_impls_ext_input;
			impls_psa_ext=impls_psa_ext_input;
			psa_latency_ext=psa_latency_ext_input;
			psa_cost_ext=psa_cost_ext_input;
		}

		public void loadExternalRepresentationFromFile(String filename){
			// read JSON file
			try {
				// read the json file
				FileReader reader = new FileReader(filename);

				JSONParser jsonParser = new JSONParser();
				JSONObject jsonObject = (JSONObject) jsonParser.parse(reader);

				// reading hspl_impls
				JSONArray hsplImpls = (JSONArray) jsonObject.get("hspl_impls");

				Iterator it = hsplImpls.iterator();
				while(it.hasNext()){
					JSONObject innerObj = (JSONObject) it.next();
					JSONObject hspl = (JSONObject) innerObj.get("hspl");
					String hsplid = (String) hspl.get("hsplid");
					JSONArray impls = (JSONArray) innerObj.get("impls");
					LinkedList l = new LinkedList();
					Iterator it1 = impls.iterator();
					while(it1.hasNext()){
						JSONObject impl = (JSONObject) it1.next();
						String implid = (String) impl.get("implid");
						l.add(implid);
					}
					hspl_impls_ext.put(hsplid, l);
				}

				// reading impl_psas
				JSONArray implPsas = (JSONArray) jsonObject.get("impl_psa");

				it = implPsas.iterator();
				while(it.hasNext()){
					JSONObject innerObj = (JSONObject) it.next();
					JSONObject impl = (JSONObject) innerObj.get("impl");
					String implid = (String) impl.get("implid");
					JSONArray psas = (JSONArray) innerObj.get("psas");
					LinkedList l = new LinkedList();
					Iterator it1 = psas.iterator();
					while(it1.hasNext()){
						JSONObject psa = (JSONObject) it1.next();
						String psaid = (String) psa.get("psaid");
						l.add(psaid);
					}
					impls_psa_ext.put(implid, l);
				}

				// reading psa latency
				JSONArray psaLatency = (JSONArray) jsonObject.get("psa_latency");
				it = psaLatency.iterator();
				while(it.hasNext()){
					JSONObject innerObj = (JSONObject) it.next();
					String id = (String) innerObj.get("id");
					String latency = (String) innerObj.get("latency");
					psa_latency_ext.put(id, latency);
				}

				// reading psa cost
				JSONArray psaCost = (JSONArray) jsonObject.get("psa_cost");
				it = psaCost.iterator();
				while(it.hasNext()){
					JSONObject innerObj = (JSONObject) it.next();
					String id = (String) innerObj.get("id");
					String cost = (String) innerObj.get("cost");
					psa_cost_ext.put(id, cost);
				}


			} catch (FileNotFoundException ex) {
				ex.printStackTrace();
			} catch (IOException ex) {
				ex.printStackTrace();
			} catch (ParseException ex) {
				ex.printStackTrace();
			} catch (NullPointerException ex) {
				ex.printStackTrace();
			}

			noVariable = impls_psa_ext.keySet().size(); // the number of impls
		}

		public void transformExternalToInternalRepresentation(){
			// transforming hspl_impls
			Iterator it = hspl_impls_ext.keySet().iterator();
			while(it.hasNext()){
				String hsplid_ext = (String) it.next();
				String hsplid_int = this.generateInternalhsplId(hsplid_ext);
				LinkedList l_ext = (LinkedList) this.hspl_impls_ext.get(hsplid_ext);
				LinkedList l_int = new LinkedList();
				Iterator it1 = l_ext.iterator();
				while(it1.hasNext()){
					String implid_ext = (String) it1.next();
					String implid_int = this.generateInternalimplId(implid_ext);
					l_int.add(implid_int);
				}
				this.hspl_impls.put(hsplid_int, l_int);
			}

			// transforming impls_psa
			it = impls_psa_ext.keySet().iterator();
			while(it.hasNext()){
				String implid_ext = (String) it.next();
				String implid_int = this.generateInternalimplId(implid_ext);
				LinkedList l_ext = (LinkedList) this.impls_psa_ext.get(implid_ext);
				LinkedList l_int = new LinkedList();
				Iterator it1 = l_ext.iterator();
				while(it1.hasNext()){
					String psaid_ext = (String) it1.next();
					String psaid_int = this.generateInternalpsaId(psaid_ext);
					l_int.add(psaid_int);
				}
				this.impls_psa.put(implid_int, l_int);
			}

			// transforming psa_latency
			it = psa_latency_ext.keySet().iterator();
			while(it.hasNext()){
				String psaid_ext = (String) it.next();
				String psaid_int = this.generateInternalpsaId(psaid_ext);
				String latency = (String) this.psa_latency_ext.get(psaid_ext);
				this.psa_latency.put(psaid_int, latency);
			}

			// transforming psa_cost
			it = psa_cost_ext.keySet().iterator();
			while(it.hasNext()){
				String psaid_ext = (String) it.next();
				String psaid_int = this.generateInternalpsaId(psaid_ext);
				String cost = (String) this.psa_cost_ext.get(psaid_ext);
				this.psa_cost.put(psaid_int, cost);
			}

		}

		public String generateInternalhsplId(String hsplid_ext){
			String result = "";

			if(!this.hspl_index.containsKey(hsplid_ext)){
				result = String.valueOf(this.hspl_i);
				this.hspl_index.put(hsplid_ext, result);
				this.hspl_i++;
			} else {
				result = (String) this.hspl_index.get(hsplid_ext);
			}

			return result;
		}

		public String generateInternalimplId(String implid_ext){
			String result = "";

			if(!this.impls_index.containsKey(implid_ext)){
				result = String.valueOf(this.impl_i);
				this.impls_index.put(implid_ext, result);
				this.impl_i++;
			} else {
				result = (String) this.impls_index.get(implid_ext);
			}

			return result;
		}

		public String generateInternalpsaId(String psaid_ext){
			String result = "";

			if(!this.psa_index.containsKey(psaid_ext)){
				result = String.valueOf(this.psa_i);
				this.psa_index.put(psaid_ext, result);
				this.psa_i++;
			} else {
				result = (String) this.psa_index.get(psaid_ext);
			}

			return result;
		}

		public void optimize(int maxEvalutationsNo){
			System.out.println();
			System.out.println("Optimization results:");

			if(maxEvalutationsNo < 1000){
				optResult = new Executor()
				.withProblemClass(PSASelectionLatencyCost.class,noVariable,2, hspl_impls, impls_psa, psa_latency, psa_cost)
				.withAlgorithm("NSGAII")
				.run();
			} else {
				optResult = new Executor()
				.withProblemClass(PSASelectionLatencyCost.class,noVariable,2, hspl_impls, impls_psa, psa_latency, psa_cost)
				.withAlgorithm("NSGAII")
				.withMaxEvaluations(maxEvalutationsNo)
				.run();
			}

		}

		public void printProblem(){
			// print hspl and implementations
			System.out.println("HSPL and Implementations:");
			Iterator it = hspl_impls_ext.keySet().iterator();
			while(it.hasNext()){
				String hsplId = (String) it.next();
				System.out.print("hspl "+ hsplId + " has implementations: ");
				LinkedList impls = (LinkedList) hspl_impls_ext.get(hsplId);
				Iterator it1 = impls.iterator();
				while(it1.hasNext()){
					String implid = (String) it1.next();
					System.out.print(implid + " ");
				}
				System.out.println();
			}
			// print implementations and psa
			System.out.println();
			System.out.println("Implementations and PSA:");
			it = impls_psa_ext.keySet().iterator();
			while(it.hasNext()){
				String implId = (String) it.next();
				System.out.print(implId + " has PSA: ");
				LinkedList psas = (LinkedList) impls_psa_ext.get(implId);
				Iterator it1 = psas.iterator();
				while(it1.hasNext()){
					String psaid = (String) it1.next();
					System.out.print(psaid + " ");
				}
				System.out.println();
			}
			// print psa latency
			System.out.println();
			System.out.println("PSA latency:");
			it = psa_latency_ext.keySet().iterator();
			while(it.hasNext())
			{
				String psaid = (String) it.next();
				System.out.println(psaid + " has latency " + psa_latency_ext.get(psaid));
			}
			// print psa cost
			System.out.println();
			System.out.println("PSA cost:");
			it = psa_cost_ext.keySet().iterator();
			while(it.hasNext())
			{
				String psaid = (String) it.next();
				System.out.println(psaid + " has cost " + psa_cost_ext.get(psaid));
			}
		}

		public void printSolution(){
			//display the results

			for(int i=0; i < this.getSolutionNumber(); i++)
			{
				HashMap sol = this.getSolution(i);
				System.out.println("Solution " + (i+1));
				System.out.println("Latency:" + sol.get("latency"));
				System.out.println("Cost:" + sol.get("cost"));
				HashMap implResult = this.getSolutionVariables(i);
				Iterator it = hspl_impls_ext.keySet().iterator();
				while(it.hasNext()){
					String hsplid = (String) it.next();
					System.out.println("hspl " + hsplid + " available implementations and results: ");
					LinkedList impls = (LinkedList) hspl_impls_ext.get(hsplid);
					Iterator it1 = impls.iterator();
					while(it1.hasNext()){
						String implId = (String) it1.next();
						System.out.println(implId + " value (1 when selected): " + implResult.get(implId));
					}
				}
			}

		}

		public int getSolutionNumber(){
			return optResult.size();
		}

		public HashMap getSolution(int number){
			HashMap result = new HashMap();
			Solution s = optResult.get(number);
			result.put("latency", s.getObjective(0));
			result.put("cost", s.getObjective(1));

			return result;
		}

		public HashMap getSolutionVariables(int solNumber){
			HashMap result = new HashMap();
			Solution s = optResult.get(solNumber);
			Iterator it = impls_index.keySet().iterator();
			while(it.hasNext()){
				String implid_ext = (String) it.next();
				String implid_int = (String) impls_index.get(implid_ext);
				int value = Integer.valueOf(s.getVariable(Integer.valueOf(implid_int)).toString());
				result.put(implid_ext, value);
			}

			return result;
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		/*
		HashMap hspl_impls = new HashMap();
		HashMap impls_psa = new HashMap();
		HashMap psa_latency = new HashMap();
		HashMap psa_cost = new HashMap();

		// read JSON file
		try {
			// read the json file
			FileReader reader = new FileReader("src/it/polito/security/MOEATests/test2.json");

			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(reader);

			// reading hspl_impls
			JSONArray hsplImpls = (JSONArray) jsonObject.get("hspl_impls");

			Iterator it = hsplImpls.iterator();
			while(it.hasNext()){
				JSONObject innerObj = (JSONObject) it.next();
				JSONObject hspl = (JSONObject) innerObj.get("hspl");
				String hsplid = (String) hspl.get("hsplid");
				JSONArray impls = (JSONArray) innerObj.get("impls");
				LinkedList l = new LinkedList();
				Iterator it1 = impls.iterator();
				while(it1.hasNext()){
					JSONObject impl = (JSONObject) it1.next();
					String implid = (String) impl.get("implid");
					l.add(implid);
				}
				hspl_impls.put(hsplid, l);
			}

			// reading impl_psas
			JSONArray implPsas = (JSONArray) jsonObject.get("impl_psa");

			it = implPsas.iterator();
			while(it.hasNext()){
				JSONObject innerObj = (JSONObject) it.next();
				JSONObject impl = (JSONObject) innerObj.get("impl");
				String implid = (String) impl.get("implid");
				JSONArray psas = (JSONArray) innerObj.get("psas");
				LinkedList l = new LinkedList();
				Iterator it1 = psas.iterator();
				while(it1.hasNext()){
					JSONObject psa = (JSONObject) it1.next();
					String psaid = (String) psa.get("psaid");
					l.add(psaid);
				}
				impls_psa.put(implid, l);
			}

			// reading psa latency
			JSONArray psaLatency = (JSONArray) jsonObject.get("psa_latency");
			it = psaLatency.iterator();
			while(it.hasNext()){
				JSONObject innerObj = (JSONObject) it.next();
				String id = (String) innerObj.get("id");
				String latency = (String) innerObj.get("latency");
				psa_latency.put(id, latency);
			}

			// reading psa cost
			JSONArray psaCost = (JSONArray) jsonObject.get("psa_cost");
			it = psaCost.iterator();
			while(it.hasNext()){
				JSONObject innerObj = (JSONObject) it.next();
				String id = (String) innerObj.get("id");
				String cost = (String) innerObj.get("cost");
				psa_cost.put(id, cost);
			}


		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (ParseException ex) {
			ex.printStackTrace();
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		}


		// simple problem
		// hspl0: impl0, impl1
		// hspl1: impl0
		// impl0: psa0, psa1
		// impl1: psa1, psa2
		/*
		LinkedList h0list0 = new LinkedList();
		h0list0.add("0");
		h0list0.add("1");
		hspl_impls.put("0", h0list0);
		LinkedList h1list0 = new LinkedList();
		h1list0.add("0");
		hspl_impls.put("1", h1list0);
		*/
		/*
		LinkedList impl0psa = new LinkedList();
		impl0psa.add("0");
		impl0psa.add("1");
		impls_psa.put("0", impl0psa);
		LinkedList impl1psa = new LinkedList();
		impl1psa.add("1");
		impl1psa.add("2");
		impls_psa.put("1", impl1psa);

		psa_latency.put("0", "0.1");
		psa_latency.put("1", "0.2");
		psa_latency.put("2", "0.3");

		psa_cost.put("0", "1");
		psa_cost.put("1", "3");
		psa_cost.put("2", "2.5");
		*/

		/*
		int noVariable = impls_psa.keySet().size(); // the number of impls


		// print hspl and implementations
		System.out.println("HSPL and Implementations:");
		Iterator it = hspl_impls.keySet().iterator();
		while(it.hasNext()){
			String hsplId = (String) it.next();
			System.out.print("hspl"+ hsplId + " has implementations: ");
			LinkedList impls = (LinkedList) hspl_impls.get(hsplId);
			Iterator it1 = impls.iterator();
			while(it1.hasNext()){
				String implid = (String) it1.next();
				System.out.print("impl" + implid + " ");
			}
			System.out.println();
		}
		// print implementations and psa
		System.out.println();
		System.out.println("Implementations and PSA:");
		it = impls_psa.keySet().iterator();
		while(it.hasNext()){
			String implId = (String) it.next();
			System.out.print("impl" + implId + " has PSA: ");
			LinkedList psas = (LinkedList) impls_psa.get(implId);
			Iterator it1 = psas.iterator();
			while(it1.hasNext()){
				String psaid = (String) it1.next();
				System.out.print("psa" + psaid + " ");
			}
			System.out.println();
		}
		// print psa latency
		System.out.println();
		System.out.println("PSA latency:");
		it = psa_latency.keySet().iterator();
		while(it.hasNext())
		{
			String psaid = (String) it.next();
			System.out.println("psa" + psaid + " has latency " + psa_latency.get(psaid));
		}
		// print psa cost
		System.out.println();
		System.out.println("PSA cost:");
		it = psa_cost.keySet().iterator();
		while(it.hasNext())
		{
			String psaid = (String) it.next();
			System.out.println("psa" + psaid + " has cost " + psa_cost.get(psaid));
		}

		// optimization
		System.out.println();
		System.out.println("Optimization results:");
		NondominatedPopulation result = new Executor()
		.withProblemClass(PSASelectionLatencyCost.class,noVariable,2, hspl_impls, impls_psa, psa_latency, psa_cost)
		.withAlgorithm("NSGAII")
		.withMaxEvaluations(1000)
		.run();

		//display the results
		int i = 0;
		for (Solution solution : result) {
			i++;
			System.out.println("Solution " + i);
			System.out.print("Latency:" + solution.getObjective(0));
			System.out.print(" ");
			System.out.print("Cost:" + solution.getObjective(1));
			System.out.println();
			it = hspl_impls.keySet().iterator();
			while(it.hasNext())
			{
				String hsplid = (String) it.next();
				System.out.println("hspl" + hsplid + " available implementations and results: ");
				LinkedList impls = (LinkedList) hspl_impls.get(hsplid);
				Iterator it1 = impls.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					System.out.println("impl" + implId + " value (1 when selected): " + solution.getVariable(Integer.parseInt(implId)));
				}
			}
			System.out.println();
		}

		/*
		String[] algorithms = { "NSGAII", "eMOEA" };

		//setup the experiment
		Executor executor = new Executor()
				.withProblemClass(MyProblem.class)
				.withMaxEvaluations(10000);

		//display the results


		Analyzer analyzer = new Analyzer()
				.withProblemClass(MyProblem.class)
				.includeHypervolume()
				.showStatisticalSignificance();

		//run each algorithm for 50 seeds
		for (String algorithm : algorithms) {
			analyzer.addAll(algorithm, executor.withAlgorithm(algorithm).runSeeds(50));
		}

		//print the results
		try {
			analyzer.printAnalysis();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/

		OptWrapper w = new OptWrapper();
		w.loadExternalRepresentationFromFile("src/it/polito/security/MOEATests/test2.json");
		w.transformExternalToInternalRepresentation();
		w.printProblem();
		w.optimize(0);
		w.printSolution();
		//System.out.println("Solution size: " +w.getSolutionNumber() );
		//System.out.println(w.getSolution(0));
		//System.out.println(w.getSolutionVariables(0));
	}


}
