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

import main.java.hspl_class.Capability;
import main.java.hspl_class.Edge;
import main.java.hspl_class.Mapping;
import main.java.hspl_class.PSA;
import main.java.hspl_class.PSAList;
import main.java.hspl_class.Service;
import main.java.hspl_class.ServiceGraph;
import main.java.hspl_class.Solution;
import main.java.hspl_class.SolutionList;

import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.fp7.secured.spm.h2mservice.impl.H2mserviceImpl;
import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.RefinementType;

public class SG_Generator {
    private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);




	public static Mapping getServiceGraph(Mapping map){
		Mapping map_sg=new Mapping();


		Solution sol=map.getSolution().getSolutions().get(0);
		ServiceGraph sg=new ServiceGraph();
		Service s;
		Service s_old = null;
		Edge e;
		int i=0;
		int n=sol.getPsaList().getPsa().size()-1;
		String id,id2;

		for (PSA p: sol.getPsaList().getPsa()){

			s=new Service();
			s.setPSA(p);
			id="Service"+i;

			s.setServiceID(id);

			if(sg.getService().isEmpty()){
				sg.setRootService(s);
				s_old=s;
			}else{
				//id2="Service"+(i+1);
				e=new Edge();
				e.setSrcService(s_old);
				e.setDstService(s);
				s_old=s;
				sg.getEdge().add(e);
			}
			if(sg.getService().size()==n){
			sg.setEndService(s);
			}

			sg.getService().add(s);
			i++;


		}

		map_sg.setServiceGraph(sg);

		return map_sg;

	}
	public static Mapping updateServiceGraph(Mapping map){

		Mapping map_sg=new Mapping();
		boolean b=false;
		List<PSA> psa_list=map.getPsaList().getPsa();
		String str1 = null,str2;
		for(Service s: map.getServiceGraph().getService()){
			if(s.getPSA()==null){
				for(PSA p: psa_list){
					str2=s.getCapability().toString();
					for(Capability c: p.getCapability().getCapabilityList()){
						str1=c.toString();
						if(str1.equals(str2)){
							s.setPSA(p);
							b=true;
							break;
						}
					}
					if(b)
						break;
				}
			}

		}
		map_sg.setServiceGraph(map.getServiceGraph());
		return map_sg;

	}
	public static void orderingSolution (Solution s, Solution s_ord){

		HashMap<Capability, PSAList> m= new HashMap();
		for(Capability c: Capability.values()){
			m.put(c, new PSAList());
		}

		PSAList l;
		for (PSA p: s.getPsaList().getPsa()){
			l= m.get(p.getCapability().getCapabilityList().get(0));
			l.getPsa().add(p);
		}

		s_ord.getPsaList().getPsa().addAll(m.get(Capability.TIMING).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.FILTERING_L_4).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.FILTERING_DNS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.FILTERING_3_G_4_G).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.FILTERING_L_7).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.BASIC_PARENTAL_CONTROL).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ADVANCED_PARENTAL_CONTROL).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.TRAFFIC_INSPECTION_L_7).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.NETWORK_TRAFFIC_ANALYSIS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.LAWFUL_INTERCEPTION).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.AUTHORISE_ACCESS_RESURCE).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.COUNT_L_4_CONNECTION).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.COUNT_DNS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.LOGGING).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ONLINE_SECURITY_ANALYZER).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ONLINE_ANTIVIRUS_ANALYSIS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ANTI_PHISHING).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ONLINE_SPAM_ANALYSIS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.OFFLINE_MALWARE_ANALYSIS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.REDUCE_BANDWIDTH).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.COMPRESS).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.PROTECTION_INTEGRITY).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.PROTECTION_CONFIDENTIALITY).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.REENCRYPT).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.IP_SEC_PROTOCOL).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.TLS_PROTOCOL).getPsa());

		s_ord.getPsaList().getPsa().addAll(m.get(Capability.D_DOS_ATTACK_PROTECTION).getPsa());
		s_ord.getPsaList().getPsa().addAll(m.get(Capability.ANONIMITY).getPsa());


	}
	public static void orderingAllSolution(Mapping map){

		SolutionList l =new SolutionList();
		Solution s_ord;
		for(Solution s: map.getSolution().getSolutions()){
			s_ord=new Solution();
			s_ord.setPsaList(new PSAList());
			orderingSolution(s, s_ord);
			l.getSolutions().add(s_ord);
		}
		map.setSolution(l);


	}



	public static void run (Mapping map, Configurations conf, Schemas schemas){
		System.out.println("Service Graph generator ");

		Mapping map_sg=null;




		if  ((conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL_SG)||(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG)))&&  map.isMix() ){
			map_sg=updateServiceGraph(map);
			Useful.mashal(map_sg, conf.getSgOuputFile(), Mapping.class);
			Initialization.printSG_simple(map_sg);
		}

		else{
			orderingAllSolution(map);
			map_sg= getServiceGraph(map);
			Useful.mashal(map_sg, conf.getSgOuputFile(), Mapping.class);
			Initialization.printSG_simple(map_sg);

		}


		System.out.println();
		System.out.println();



	}

	public static void run (Configuration conf){
		System.out.println("Service Graph generator ");

		Mapping map_sg=null;




		if  ((conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL_SG)||(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG)))&&  conf.getMap().isMix() ){
			//map_sg=updateServiceGraph(conf.getMap());
			map_sg= getServiceGraph(conf.getMap());

			//Useful.mashal(map_sg, conf.getSgOuputFile(), Mapping.class);
			Initialization.printSG_simple(map_sg);
		}

		else{
			orderingAllSolution(conf.getMap());
			map_sg= getServiceGraph(conf.getMap());
			//Useful.mashal(map_sg, conf.getSgOuputFile(), Mapping.class);
			Initialization.printSG_simple(map_sg);

		}

		conf.getMap().setServiceGraph(map_sg.getServiceGraph());

		System.out.println();
		System.out.println();


	}

}
