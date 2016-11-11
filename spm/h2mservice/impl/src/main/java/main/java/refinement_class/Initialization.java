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

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashSet;

import javax.sound.sampled.AudioFormat.Encoding;

import org.kie.api.KieBase;
import org.kie.api.KieServices;
import org.kie.api.builder.KieBuilder;
import org.kie.api.builder.KieFileSystem;
import org.kie.api.builder.KieRepository;
import org.kie.api.builder.Message;
import org.kie.api.builder.Message.Level;
import org.kie.api.builder.Results;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.fp7.secured.spm.h2mservice.impl.H2mserviceImpl;
import main.java.schemaFile_class.Schemas;
import main.java.hspl_class.Action;
import main.java.hspl_class.Candidates;
import main.java.hspl_class.Capability;
import main.java.hspl_class.CapabilityList;
import main.java.hspl_class.Edge;
import main.java.hspl_class.Fields;
import main.java.hspl_class.HSPLList;
import main.java.hspl_class.Hspl;
import main.java.hspl_class.MSPL;
import main.java.hspl_class.MSPLList;
import main.java.hspl_class.Mapping;
import main.java.hspl_class.ObjectH;
import main.java.hspl_class.PSA;
import main.java.hspl_class.PSAList;
import main.java.hspl_class.Service;
import main.java.hspl_class.SuitableImplementationList;
import main.java.hspl_class.SuitablePSA;
import main.java.hspl_class.TrafficTarget;
import main.java.mspl_class.ITResource;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.OptimizationType;
import main.java.configuration_class.RefinementType;

import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenStream;


public class Initialization {
	private static final Logger LOG = LoggerFactory.getLogger(H2mserviceImpl.class);

	public static void loadDrools(){
		KieSession kieSession = null;
		try {
			kieSession = Useful.build("/rules/HSPL_rules.drl","src/main/resources/HSPL_rules.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//kieSession.insert(h);
		kieSession.fireAllRules();
	}

	public static void getPSAtoServiceGraph(Mapping map, String sg_file, String s_psa ) throws MalformedURLException{

		String s_schema="/refinement/schema/Refinement_Schema.xsd";
		//		String s_psa="/refinement/java/input/PSA.xml";



		Mapping map_sg=(Mapping) Useful.unmashal(s_schema, sg_file, Mapping.class);
		map.setPsaList(new PSAList());
		map.setServiceGraph(map_sg.getServiceGraph());
		Mapping map_psa=(Mapping) Useful.unmashal(s_schema, s_psa,Mapping.class);

		for(Service ser: map_sg.getServiceGraph().getService()){

			if(ser.getPSA()==null){
				map.setMix(true);
				for(PSA p: map_psa.getPsaList().getPsa()){
					if (p.getCapability().getCapabilityList().contains(ser.getCapability()))
						map.getPsaList().getPsa().add(p);
				}
			}else{

				map.getPsaList().getPsa().add(ser.getPSA());
			}
		}


	}

	public static void printHSPLs(Mapping map_hspl){
		System.out.println("-HSPLs:");
		for (Hspl h: map_hspl.getHsplList().getHspl()){
			PSA_Selection.printHSPL_compact(h);
		}
	}

	public static  void printMSPL( Mapping map){
		for(MSPL mspl: map.getMsplList().getMsplList()){
			System.out.print("  -"+mspl.getId()+ ":");
			for(Capability c: mspl.getCapabilities().getCapabilityList()){
				System.out.print(c.toString()+ ",");
			}
			System.out.println();
		}
	}

	public static void printPSAs(Mapping map) {
		System.out.println("-PSA:");

		for(PSA p: map.getPsaList().getPsa()){
			PSA_Selection.printPSA(p);
		}

	}
	public static void printSG_simple(Mapping map){
		try{
			LOG.info("Mapping map: "+ map.toString());
			Service root=(Service) map.getServiceGraph().getRootService();

			HashSet< Edge> list_edge=new HashSet<Edge>();

			list_edge.addAll(map.getServiceGraph().getEdge());
			Service s=root;
			System.out.println("-Service Graph:");
			LOG.info("s: " + s.toString());
			if(s.getPSA()!=null)
				System.out.print(s.getPSA().getName());
			else
				System.out.print("*"+ s.getCapability()+"*");

			while (!list_edge.isEmpty())
				s=printEdge(list_edge,s);
		} catch (Exception e) {
			e.printStackTrace();
			LOG.error("printSG_simple \n\n" + Useful.getStackTrace(e));
		}
	}



	private static Service printEdge(HashSet<Edge> list_edge, Service s) {
		Edge edge = null;
		for(Edge e: list_edge){
			if(e.getSrcService().equals(s)){
				edge=e;
				break;
			}

		}
		list_edge.remove(edge);
		Service dest=(Service) edge.getDstService();

		if(dest.getPSA()!=null)
			System.out.print("->"+dest.getPSA().getName());
		else
			System.out.print("->*"+ dest.getCapability()+"*");

		return dest;
	}
	public static void checkConfiguration(Configurations conf){

		if(conf.getOptimizationType()==null)
			conf.setOptimizationType(OptimizationType.MIN_BUY_COSTMIN_LATENCY);

		if(conf.getPsaFile()==null)
			conf.setPsaFile("/refinement/auxiliary_files/input/PSA/PSA_Alice.xml");

		/*if(conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL) && conf.getSgInputFile()==null){
			System.err.println("Configuration Error: sg file missing");
			System.exit(-1);
		}*/

		if(conf.getSgOuputFile()==null)
			conf.setSgOuputFile("/refinement/auxiliary_files/output/Output_SG.xml");

		if(conf.getMsplDirOutput()==null)
			conf.setMsplDirOutput("/refinement/auxiliary_files/output/MSPL/");

		if(conf.getMsplDirInput()==null)
			conf.setMsplDirInput("/refinement/auxiliary_files/input/MSPL/");

		if(conf.getSubjectFile()==null)
			conf.setSubjectFile("/refinement/auxiliary_files/input/Subject.xml");

		if(conf.getContentFile()==null)
			conf.setContentFile("/refinement/auxiliary_files/input/Content.xml");

		if(conf.getTargetFile()==null)
			conf.setTargetFile("/refinement/auxiliary_files/input/Target.xml");

		if(conf.getMaxEvaluationsNo()==null)
			conf.setMaxEvaluationsNo(0);


	}




	public static void run (Mapping map, Configurations conf, Schemas schema){

		System.out.println("______________________________________________________________________________");
		System.out.println("Load Drools libraries");
		loadDrools();
		System.out.println("_______________________________________________________________________________");
		System.out.println();
		System.out.println();
		System.out.println();
		System.out.println();




		//checkConfiguration(conf);

		String s_schema=schema.getRefinementSchema();
		String m_schema=schema.getMSPLXMLSchema();
		System.setProperty("drools.dialect.mvel.strict", "false");




		Mapping map_hspl=null,map_mspl=null,
				map_userPSA=null, market_PSA=null,
				map_psa=null;
		//map= new Mapping();

		System.out.println("Initialization phase:");

		if(conf.getRefinementType().equals(RefinementType.POLICY_HSPL)){
			System.out.println("-Type of refinement: Policy Driven whit HSPL");
			map_hspl=(Mapping) Useful.unmashal(s_schema, conf.getHsplFile(),Mapping.class );
			printHSPLs(map_hspl);
			map_psa=(Mapping) Useful.unmashal(s_schema, conf.getPsaFile(),Mapping.class);
			map.setPsaList(map_psa.getPsaList());
			map.setUserPsaList(map_psa.getPsaList());
			printPSAs(map);
			map.setHsplList(map_hspl.getHsplList());


		}

		else if(conf.getRefinementType().equals(RefinementType.POLICY_MSPL)){
			System.out.println("-Type of refinement: Policy Driven whit MSPL");

			File folder = new File(conf.getMsplDirInput());
			File[] listOfFiles = folder.listFiles();
			ITResource it;
			MSPL mspl;
			HashSet<ITResource> it_list=new HashSet<ITResource>();
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();

			String s;
			for(File f: listOfFiles){
				it=(ITResource) Useful.unmashal(m_schema, f.getPath(),ITResource.class );
				it_list.add(it);
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}


			}


			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			map.setMsplList(list);
			printMSPL(map);

			map_psa=(Mapping) Useful.unmashal(s_schema, conf.getPsaFile(),Mapping.class);
			map.setPsaList(map_psa.getPsaList());
			map.setUserPsaList(map_psa.getPsaList());

			printPSAs(map);

		}


		else if(conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL_SG)){

			System.out.println("-Type of refinement: Application Driven whit HSPL and SG");
			map_hspl=(Mapping) Useful.unmashal(s_schema, conf.getHsplFile(),Mapping.class );
			printHSPLs(map_hspl);
			map.setHsplList(map_hspl.getHsplList());


			try {
				getPSAtoServiceGraph( map,conf.getSgInputFile(), conf.getUserPsaFile());

			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			printSG_simple(map);

		}

		else if(conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL)){

			System.out.println("-Type of refinement: Application Driven whit HSPL");
			map_hspl=(Mapping) Useful.unmashal(s_schema, conf.getHsplFile(),Mapping.class );
			printHSPLs(map_hspl);
			map.setHsplList(map_hspl.getHsplList());

			map_psa=(Mapping) Useful.unmashal(s_schema, conf.getPsaFile(),Mapping.class);
			map.setPsaList(map_psa.getPsaList());
			printPSAs(map);



		}


		else if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG)){

			System.out.println("-Type of refinement: Application Driven whit MSPL and SG");

			//map_hspl=(Mapping) Useful.unmashal(s_schema, conf.getHsplFile(),Mapping.class );
			//printHSPLs(map_hspl);



			File folder = new File(conf.getMsplDirInput());
			File[] listOfFiles = folder.listFiles();
			ITResource it;
			MSPL mspl;
			HashSet<ITResource> it_list=new HashSet<ITResource>();
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();

			String s;
			for(File f: listOfFiles){
				it=(ITResource) Useful.unmashal(m_schema, f.getPath(),ITResource.class );
				it_list.add(it);
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}


			}


			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			map.setMsplList(list);
			printMSPL(map);




			try {
				getPSAtoServiceGraph( map,conf.getSgInputFile(), conf.getUserPsaFile());
			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			printSG_simple(map);
		}

		else if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL)){
			System.out.println("-Type of refinement: Application Driven whit MSPL");

			//map_hspl=(Mapping) Useful.unmashal(s_schema, conf.getHsplFile(),Mapping.class );
			//printHSPLs(map_hspl);



			File folder = new File(conf.getMsplDirInput());
			File[] listOfFiles = folder.listFiles();
			ITResource it;
			MSPL mspl;
			HashSet<ITResource> it_list=new HashSet<ITResource>();
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();

			String s;
			for(File f: listOfFiles){
				it=(ITResource) Useful.unmashal(m_schema, f.getPath(),ITResource.class );
				it_list.add(it);
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}


			}


			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			map.setMsplList(list);
			printMSPL(map);

			map_psa=(Mapping) Useful.unmashal(s_schema, conf.getPsaFile(),Mapping.class);
			map.setPsaList(map_psa.getPsaList());
			printPSAs(map);
		}



		if(!(conf.getRefinementType().equals(RefinementType.POLICY_HSPL)) && !(conf.getRefinementType().equals(RefinementType.POLICY_MSPL))){
			map_userPSA=(Mapping) Useful.unmashal(s_schema, conf.getUserPsaFile(),Mapping.class);
			map.setUserPsaList(map_userPSA.getPsaList());
		}


		market_PSA=(Mapping) Useful.unmashal(s_schema, conf.getMarketPsaFile(),Mapping.class);
		map.setAdditionalPsaList(market_PSA.getPsaList());



	}

	public static void run (Configuration conf){
		System.out.println("______________________________________________________________________________");
		System.out.println("Load Drools libraries");
		loadDrools();
		System.out.println("_______________________________________________________________________________");
		System.out.println();
		System.out.println();
		System.out.println();
		System.out.println();

		System.out.println("Initialization phase:");


		if(conf.getRefinementType().equals(RefinementType.POLICY_HSPL)){
			System.out.println("-Type of refinement: Policy Driven whit HSPL");
			splitHSPL(conf);
			printHSPLs(conf.getMap());
			printPSAs(conf.getMap());


		}

		else if (conf.getRefinementType().equals(RefinementType.POLICY_MSPL)){
			System.out.println("-Type of refinement: Application Driven whit MSPL and SG");


			MSPL mspl;
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();
			String s;

			for(ITResource it: conf.getMspl_list()){
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}

			}

			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			conf.getMap().setMsplList(list);


			printMSPL(conf.getMap());
			printPSAs(conf.getMap());



		}

		else if (conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL)){

			System.out.println("-Type of refinement: Application Driven whit HSPL");

			printHSPLs(conf.getMap());
			printPSAs(conf.getMap());

		}

		else if (conf.getRefinementType().equals(RefinementType.APPLICATION_HSPL_SG)){

			System.out.println("-Type of refinement: Application Driven whit HSPL and SG");
			printHSPLs(conf.getMap());






			conf.getMap().setPsaList(new PSAList());
			for(Service ser: conf.getMap().getServiceGraph().getService()){

				if(ser.getPSA()==null){
					conf.getMap().setMix(true);
					for(PSA p: conf.getMap().getUserPsaList().getPsa()){
						if (p.getCapability().getCapabilityList().contains(ser.getCapability()))
							conf.getMap().getPsaList().getPsa().add(p);
					}
				}else{

					conf.getMap().getPsaList().getPsa().add(ser.getPSA());
				}
			}


			printSG_simple(conf.getMap());

		}



		else if (conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL)){
			System.out.println("-Type of refinement: Application Driven whit MSPL");
			MSPL mspl;
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();
			String s;

			for(ITResource it: conf.getMspl_list()){
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}

			}

			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			conf.getMap().setMsplList(list);


			printMSPL(conf.getMap());
			printPSAs(conf.getMap());

		}
		else if (conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG)){

			MSPL mspl;
			HashSet<MSPL> mspl_list=new HashSet<MSPL>();
			String s;

			for(ITResource it: conf.getMspl_list()){
				mspl=new MSPL();
				mspl.setCapabilities(new CapabilityList());
				mspl.setId(it.getID());
				mspl_list.add(mspl);
				mspl.setCandidates(new Candidates());
				SuitablePSA e;
				PSAList l;
				Capability c;
				for(main.java.mspl_class.Capability it_c: it.getConfiguration().getCapability()){
					s=it_c.getName().toString();
					c=Capability.valueOf(s);
					mspl.getCapabilities().getCapabilityList().add(c);

					e=new SuitablePSA();
					e.setCapability(c);
					l= new PSAList();
					e.setPsaList(l);
					mspl.getCandidates().getSuitablePSAList().add(e);
				}

			}

			MSPLList list=new MSPLList();
			list.getMsplList().addAll(mspl_list);
			conf.getMap().setMsplList(list);


			printMSPL(conf.getMap());

			conf.getMap().setPsaList(new PSAList());
			for(Service ser: conf.getMap().getServiceGraph().getService()){

				if(ser.getPSA()==null){
					conf.getMap().setMix(true);
					for(PSA p: conf.getMap().getUserPsaList().getPsa()){
						if (p.getCapability().getCapabilityList().contains(ser.getCapability()))
							conf.getMap().getPsaList().getPsa().add(p);
					}
				}else{

					conf.getMap().getPsaList().getPsa().add(ser.getPSA());
				}
			}
			printSG_simple(conf.getMap());

		}



	}

	public static void splitHSPL(Configuration conf) {
		HSPLList listH= new HSPLList();
		listH.getHspl().addAll(conf.getMap().getHsplList().getHspl());
		Hspl newHSPL = null;
		Fields f=null;
		TrafficTarget t=null;

		for (Hspl h: conf.getMap().getHsplList().getHspl())
			if(h.getAction().equals(Action.ENABLE)&& h.getObjectH().equals(ObjectH.ADVANCE_PARENTAL_CONTROL)){
				newHSPL=new Hspl();	
				newHSPL.setId(h.getId()+"_1");
				newHSPL.setSubject(h.getSubject());
				newHSPL.setAction(Action.AUTHORISE_ACCESS);				
				newHSPL.setObjectH(ObjectH.DNS_TRAFFIC);
				f=new Fields();
				t= new TrafficTarget();
				t.getTargetName().add("family_shield_dns");
				f.setTrafficTarget(t);
				newHSPL.setFields(f);
				newHSPL.setSuitableImplementation(new SuitableImplementationList());
				newHSPL.setCapabilities(new CapabilityList());
				newHSPL.setCandidates(new Candidates());


				listH.getHspl().add(newHSPL);


				newHSPL=new Hspl();
				newHSPL.setId(h.getId()+"_2");
				newHSPL.setSubject(h.getSubject());
				newHSPL.setAction(Action.NO_AUTHORISE_ACCESS);
				newHSPL.setObjectH(ObjectH.INTERNET_TRAFFIC);
				f=new Fields();
				t= new TrafficTarget();
				t.getTargetName().add("antiparental_control_proxies");
				f.setTrafficTarget(t);
				newHSPL.setFields(f);
				newHSPL.setSuitableImplementation(new SuitableImplementationList());
				newHSPL.setCapabilities(new CapabilityList());
				newHSPL.setCandidates(new Candidates());

				listH.getHspl().add(newHSPL);
			}

		conf.getMap().setHsplList(listH);

	}





}
