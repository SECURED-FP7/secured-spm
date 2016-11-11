/**********************************************************************************************
 * Copyright (c) 2016 Politecnico di Torino.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *   - POLITO TorSec Team: Fulvio Valenza, Christian Pitscheider, Cataldo Basile, Marco Vallini 
 *	 - SECURED Team 
 *	 - Corresponding: fulvio.valenza@polito.it, cataldo.basile@polito.it
 ************************************************************************************************/
package main.java.refinement_class;

import main.java.hspl_class.Hspl;
import main.java.hspl_class.MSPL;
import main.java.hspl_class.Mapping;
import main.java.hspl_class.PSA;
import main.java.hspl_class.PSAList;
import main.java.hspl_class.Solution;
import main.java.hspl_class.SolutionList;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;

import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.OptimizationType;
import main.java.configuration_class.RefinementType;

public class Optimization {


	public static  void psaSelection_minTranferCostminLatency(Mapping map, int maxEvaluationsNo){

		PSA_minTransferCostminLatency.OptWrapper w = new PSA_minTransferCostminLatency.OptWrapper();

		HashMap hspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_latency_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap hspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_hspl=0;
		Integer var_impl=0;


		for(Hspl h: map.getHsplList().getHspl()){

			impls_list= new LinkedList();
			hspls.put(var_hspl.toString(), h);

			for (PSAList i : h.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			hspl_impls_ext_input.put(var_hspl.toString(), impls_list);
			var_hspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_latency_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getLatency()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(hspl_impls_ext_input, impls_psa_ext_input, psa_latency_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			s.setLatency((Double) sol.get("latency"));
			//s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			Hspl h;
			while(it.hasNext()){
				String hsplid = (String) it.next();
				h=(Hspl) hspls.get(hsplid);
				h.setImplementation(new PSAList());
				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(hsplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						h.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);
					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}









	}
	public static void psaSelection_minBuyCostminLatency(Mapping map, int maxEvaluationsNo){
		PSA_minBuyCostminLatency.OptWrapper w = new PSA_minBuyCostminLatency.OptWrapper();

		HashMap hspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_latency_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap hspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_hspl=0;
		Integer var_impl=0;



		for(Hspl h: map.getHsplList().getHspl()){

			impls_list= new LinkedList();
			hspls.put(var_hspl.toString(), h);

			for (PSAList i : h.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			hspl_impls_ext_input.put(var_hspl.toString(), impls_list);
			var_hspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_latency_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getLatency()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(hspl_impls_ext_input, impls_psa_ext_input, psa_latency_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			s.setLatency((Double) sol.get("latency"));
			//s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			Hspl h;
			while(it.hasNext()){
				String hsplid = (String) it.next();
				h=(Hspl) hspls.get(hsplid);
				h.setImplementation(new PSAList());
				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(hsplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						h.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);


					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}








	}
	public static void psaSelection_minBuyCostmaxRating(Mapping map, int maxEvaluationsNo){

		//PSA_minBuyCostmaxRating.OptWrapper w = new PSA_minBuyCostmaxRating.OptWrapper();
	    PSA_minBuyCostmaxRating w = new PSA_minBuyCostmaxRating();
		HashMap hspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_rating_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap hspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_hspl=0;
		Integer var_impl=0;



		for(Hspl h: map.getHsplList().getHspl()){

			impls_list= new LinkedList();
			hspls.put(var_hspl.toString(), h);

			for (PSAList i : h.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			hspl_impls_ext_input.put(var_hspl.toString(), impls_list);
			var_hspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_rating_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getRating()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(hspl_impls_ext_input, impls_psa_ext_input, psa_rating_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			//s.setLatency((Double) sol.get("latency"));
			s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			Hspl h;

			while(it.hasNext()){
				String hsplid = (String) it.next();
				h=(Hspl) hspls.get(hsplid);
				h.setImplementation(new PSAList());

				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(hsplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						h.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);
					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}



	}


	private static void psaSelection_minBuyCostmaxRating_mspl(Mapping map,int maxEvaluationsNo) {
		//PSA_minTransferCostminLatency.OptWrapper w = new PSA_minTransferCostminLatency.OptWrapper();
		
	    PSA_minBuyCostmaxRating w = new PSA_minBuyCostmaxRating();
		HashMap mspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_latency_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap mspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_mspl=0;
		Integer var_impl=0;


		for(MSPL m: map.getMsplList().getMsplList()){

			impls_list= new LinkedList();
			mspls.put(var_mspl.toString(), m);

			for (PSAList i : m.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			mspl_impls_ext_input.put(var_mspl.toString(), impls_list);
			var_mspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_latency_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getLatency()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(mspl_impls_ext_input, impls_psa_ext_input, psa_latency_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			s.setLatency((Double) sol.get("latency"));
			//s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			MSPL m;
			while(it.hasNext()){
				String msplid = (String) it.next();
				m=(MSPL) mspls.get(msplid);
				m.setImplementation(new PSAList());
				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(msplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						m.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);
					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}


	}
	private static void psaSelection_minBuyCostminLatency_mspl(Mapping map,int maxEvaluationsNo) {
		PSA_minBuyCostminLatency.OptWrapper w = new PSA_minBuyCostminLatency.OptWrapper();

		HashMap mspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_latency_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap mspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_mspl=0;
		Integer var_impl=0;


		for(MSPL m: map.getMsplList().getMsplList()){

			impls_list= new LinkedList();
			mspls.put(var_mspl.toString(), m);

			for (PSAList i : m.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			mspl_impls_ext_input.put(var_mspl.toString(), impls_list);
			var_mspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_latency_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getLatency()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(mspl_impls_ext_input, impls_psa_ext_input, psa_latency_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			s.setLatency((Double) sol.get("latency"));
			//s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			MSPL m;
			while(it.hasNext()){
				String msplid = (String) it.next();
				m=(MSPL) mspls.get(msplid);
				m.setImplementation(new PSAList());
				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(msplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						m.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);
					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}

	}
	private static void psaSelection_minTranferCostminLatency_mspl(Mapping map,int maxEvaluationsNo) {
		PSA_minTransferCostminLatency.OptWrapper w = new PSA_minTransferCostminLatency.OptWrapper();

		HashMap mspl_impls_ext_input = new HashMap();
		HashMap impls_psa_ext_input = new HashMap();
		HashMap psa_latency_ext_input = new HashMap();
		HashMap psa_cost_ext_input = new HashMap();
		LinkedList impls_list;
		LinkedList psa_list;


		HashMap mspls= new HashMap();
		HashMap impls= new HashMap();

		Integer var_mspl=0;
		Integer var_impl=0;


		for(MSPL m: map.getMsplList().getMsplList()){

			impls_list= new LinkedList();
			mspls.put(var_mspl.toString(), m);

			for (PSAList i : m.getSuitableImplementation().getSubitableImplementation()){
				impls.put(var_impl.toString(), i);
				impls_list.add(var_impl.toString());
				psa_list=new LinkedList();
				for(PSA p: i.getPsa()){
					psa_list.add(p.getName());

				}
				impls_psa_ext_input.put(var_impl.toString(), psa_list);
				var_impl++;


			}
			mspl_impls_ext_input.put(var_mspl.toString(), impls_list);
			var_mspl++;


		}

		for(PSA p: map.getPsaList().getPsa()){
			psa_latency_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getLatency()));
			psa_cost_ext_input.put(p.getName(), Double.toString(p.getPSACharacteristic().getCost()));

		}


		w.loadExternalRepresentation(mspl_impls_ext_input, impls_psa_ext_input, psa_latency_ext_input, psa_cost_ext_input);
		w.transformExternalToInternalRepresentation();
		//w.printProblem();
		w.optimize(maxEvaluationsNo);
		//w.printSolution();





		map.setSolution(new SolutionList());
		Solution s;

		for(int i=0; i < w.getSolutionNumber(); i++)
		{

			HashMap sol = w.getSolution(i);

			s=new Solution();
			PSAList lp=new PSAList();
			s.setPsaList(lp);
			s.setCost((Double) sol.get("cost"));
			s.setLatency((Double) sol.get("latency"));
			//s.setRating( (Double) sol.get("rating"));

			HashMap implResult = w.getSolutionVariables(i);


			Iterator it = w.hspl_impls_ext.keySet().iterator();
			MSPL m;
			while(it.hasNext()){
				String msplid = (String) it.next();
				m=(MSPL) mspls.get(msplid);
				m.setImplementation(new PSAList());
				//	System.out.println("hspl " + hsplid + " available implementations and results: ");
				LinkedList impls2 = (LinkedList) w.hspl_impls_ext.get(msplid);
				Iterator it1 = impls2.iterator();
				while(it1.hasNext()){
					String implId = (String) it1.next();
					if(implResult.get(implId).toString().equals("1")){

						PSAList l1=(PSAList) impls.get(implId);
						m.getImplementation().getPsa().addAll(l1.getPsa());

						for(PSA p: l1.getPsa())
							if(!s.getPsaList().getPsa().contains(p))
								s.getPsaList().getPsa().add(p);
					}

				}

			}
			map.getSolution().getSolutions().add(s);

		}

	}




	public static void printSolution(Mapping map){
		int i=0;
		for(Solution s : map.getSolution().getSolutions()){
		System.out.println("Solution "+i+ ":");

		if(s.getCost()!=null)
			System.out.println("-Cost: "+s.getCost());

		if(s.getLatency()!=null)
			System.out.println("-Latency: "+s.getLatency());

		if(s.getRating()!=null)
			System.out.println("-Rating: "+s.getRating());

		System.out.print("PSAs: {");

		for(PSA p: s.getPsaList().getPsa())
			System.out.print(p.getName() +", ");
		System.out.println("}");

		}

	}

	public static void run(Mapping map, Configurations conf, Schemas schemas ){


		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL) ||conf.getRefinementType().equals(RefinementType.POLICY_MSPL) ){
			if(conf.getOptimizationType().equals(OptimizationType.MIN_TRANFER_COSTMIN_LATENCY))
				psaSelection_minTranferCostminLatency_mspl(map,conf.getMaxEvaluationsNo() );

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMIN_LATENCY))
					psaSelection_minBuyCostminLatency_mspl(map,conf.getMaxEvaluationsNo());

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMAX_RATING))
				psaSelection_minBuyCostmaxRating_mspl(map,conf.getMaxEvaluationsNo());

		}

		else {
			//System.out.println("Step 5: Selection solution");

			if(conf.getOptimizationType().equals(OptimizationType.MIN_TRANFER_COSTMIN_LATENCY))
				psaSelection_minTranferCostminLatency(map,conf.getMaxEvaluationsNo() );

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMIN_LATENCY))
					psaSelection_minBuyCostminLatency(map,conf.getMaxEvaluationsNo());

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMAX_RATING))
				psaSelection_minBuyCostmaxRating(map,conf.getMaxEvaluationsNo());

			}


		printSolution(map);

		System.out.println();

	}
	public static void run (Configuration conf){


		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL) ||conf.getRefinementType().equals(RefinementType.POLICY_MSPL)){
			if(conf.getOptimizationType().equals(OptimizationType.MIN_TRANFER_COSTMIN_LATENCY))
				psaSelection_minTranferCostminLatency_mspl(conf.getMap(),conf.getMaxEvaluationsNo() );

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMIN_LATENCY))
					psaSelection_minBuyCostminLatency_mspl(conf.getMap(),conf.getMaxEvaluationsNo());

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMAX_RATING))
				psaSelection_minBuyCostmaxRating_mspl(conf.getMap(),conf.getMaxEvaluationsNo());

		}

		else {
			//System.out.println("Step 5: Selection solution");

			if(conf.getOptimizationType().equals(OptimizationType.MIN_TRANFER_COSTMIN_LATENCY))
				psaSelection_minTranferCostminLatency(conf.getMap(),conf.getMaxEvaluationsNo() );

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMIN_LATENCY))
					psaSelection_minBuyCostminLatency(conf.getMap(),conf.getMaxEvaluationsNo());

			else if(conf.getOptimizationType().equals(OptimizationType.MIN_BUY_COSTMAX_RATING))
				psaSelection_minBuyCostmaxRating(conf.getMap(),conf.getMaxEvaluationsNo());

			}


		printSolution(conf.getMap());

		System.out.println();



	}

}
