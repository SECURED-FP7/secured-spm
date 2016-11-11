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
import java.util.List;
import java.util.Stack;

import org.kie.api.runtime.KieSession;

import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.RefinementType;
import main.java.hspl_class.Candidates;
import main.java.hspl_class.Capability;
import main.java.hspl_class.CapabilityList;
import main.java.hspl_class.Fields;
import main.java.hspl_class.Hspl;
import main.java.hspl_class.MSPL;
import main.java.hspl_class.Mapping;
import main.java.hspl_class.PSA;
import main.java.hspl_class.PSAList;
import main.java.hspl_class.RemediationList;
import main.java.hspl_class.Remediationt;
import main.java.hspl_class.SuitableImplementationList;
import main.java.hspl_class.SuitablePSA;
import main.java.hspl_class.TimeHour;
import main.java.hspl_class.TimeInterval;
import main.java.hspl_class.WeekDay;

public class PSA_Selection {



	public static  void printMSPL ( MSPL mspl){
			System.out.print("  -"+mspl.getId()+ ":<");
			for(Capability c: mspl.getCapabilities().getCapabilityList()){
				System.out.print(c.toString()+ ",");
			}
			System.out.println(">");

			System.out.print("  Suitable Implementation: {");

			for (PSAList l: mspl.getSuitableImplementation().getSubitableImplementation()){
				System.out.print("(");
				for (PSA p: l.getPsa()){
					System.out.print(p.getName()+", ");

				}
				System.out.print("),  ");
			}
			System.out.println("}");

	}






	public static void printHSPL(Hspl h){
		//	System.out.println("-------------------------------------------------");
		System.out.print("HSPL"+h.getId()+ ":" );

		System.out.println("-Subject:"+h.getSubject());
		System.out.println("-Action:"+h.getAction().toString());
		System.out.println("-Object:"+h.getObjectH().toString());
		System.out.println("-Field:");

		Fields f = h.getFields();
		if(f.getUplinkBandwidthValue()!=null)
			System.out.println("--Bandwidth Uplink:"+f.getUplinkBandwidthValue() );
		
		if(f.getDownlinkBandwidthValue()!=null)
			System.out.println("--Bandwidth Downlink:"+f.getDownlinkBandwidthValue() );

		if(f.getResourceValues()!=null){
			System.out.print("--Resurce: ");

			for(String i : f.getResourceValues().getNameResurces())
				System.out.print(i+", ");
			System.out.println();

		}

		if(f.getPurpose()!=null){

			System.out.print("--Purpose: ");

			for(String i : f.getPurpose().getPurposeName())
				System.out.print(i+", ");
			System.out.println();

		}


		if(f.getSpecificURL()!=null){
			System.out.print("--URL: ");

			for(String i : f.getSpecificURL().getURL())
				System.out.print(i+", ");
			System.out.println();

		}


		if(f.getTypeContent()!=null){
			System.out.print("--TypeContent: ");

			for(String i : f.getTypeContent().getContentName())
				System.out.print(i+", ");
			System.out.println();

		}


		if(f.getTrafficTarget()!=null){
			System.out.print("--TrafficTarget: ");

			for(String i : f.getTrafficTarget().getTargetName())
				System.out.print(i+", ");
			System.out.println();

		}

		/*if(f.getTimePeriod()!=null){
			System.out.print("--Time Period: ");

			for(TimeInterval i : f.getTimePeriod().getIntervalTime()){
				System.
				for()
				System.out.print( "("+i.getStartTime()+","+i.getEndTime()+"), ");


			}
			System.out.println(f.getTimePeriod().getTimeZone());

		}*/
		System.out.println();
		System.out.println("HSPL Capability:");

		for( Capability c :h.getCapabilities().getCapabilityList()){
			System.out.println("-"+c);
		}
		System.out.println("---------------------------------------------------");

		System.out.println();
		System.out.println("SuitablePSA Capability:");

		for(SuitablePSA s:h.getCandidates().getSuitablePSAList()){
			System.out.println("-List PSA for cabability:"+ s.getCapability().value() );
			for(PSA p: s.getPsaList().getPsa())
				System.out.println("--"+p.getName());
			System.out.println();

		}

		System.out.println("---------------------------------------------------");

		System.out.println();
		System.out.println("suitable Implementation:");
		for (PSAList l: h.getSuitableImplementation().getSubitableImplementation()){
			System.out.print("-");
			for (PSA p: l.getPsa()){
				System.out.print(p.getName()+", ");

			}
			System.out.println();

		}
	}

	public static void printHSPL_compact(Hspl h){

		System.out.print("  -"+h.getId()+ ":" +h.getSubject()+" "+ h.getAction().toString()+ " " + h.getObjectH().toString()+" " );

		if(h.getFields()!=null){
			Fields f = h.getFields();
			if(f.getUplinkBandwidthValue()!=null)
				System.out.println("--Bandwidth Uplink:"+f.getUplinkBandwidthValue() );
			
			if(f.getDownlinkBandwidthValue()!=null)
				System.out.println("--Bandwidth Downlink:"+f.getDownlinkBandwidthValue() );

			if(f.getResourceValues()!=null){
				//System.out.print("--Resurce: ");

				for(String i : f.getResourceValues().getNameResurces())
					System.out.print(i+", ");
				System.out.print(" ");

			}

			if(f.getPurpose()!=null){

				//System.out.print("--Purpose: ");

				for(String i : f.getPurpose().getPurposeName())
					System.out.print(i+", ");
				System.out.print(" ");

			}


			if(f.getSpecificURL()!=null){
				//System.out.print("--URL: ");

				for(String i : f.getSpecificURL().getURL())
					System.out.print(i+", ");
				System.out.print(" ");

			}


			if(f.getTypeContent()!=null){
				//System.out.print("--TypeContent: ");

				for(String i : f.getTypeContent().getContentName())
					System.out.print(i+", ");
				System.out.print(" ");

			}


			if(f.getTrafficTarget()!=null){
				//System.out.print("--TrafficTarget: ");

				for(String i : f.getTrafficTarget().getTargetName())
					System.out.print(i+", ");
				System.out.print(" ");

			}

			if(f.getTimePeriod()!=null){
				//System.out.print("--Time Period: ");

				for(TimeInterval i : f.getTimePeriod().getIntervalTime()){
					System.out.print("(");

					if(i.getWeekDay()!=null)
						System.out.print("< ");

					for(WeekDay d:i.getWeekDay()){
						System.out.print(d.toString()+", ");
					}
					System.out.print("> ");
					if(i.getTimeHours()!=null){
						System.out.print("< ");
						for(TimeHour hour: i.getTimeHours()){
							System.out.print( hour.getStartTime()+"-"+hour.getEndTime()+", ");

						}
						System.out.print("> ");
					}
					System.out.print( f.getTimePeriod().getTimeZone()+ ")");


				}

			}

		}
		System.out.println();


	}

	public static void printHSPL2 (Hspl h){
		System.out.println("-"+h.getId()+ ": " );

		System.out.print("  Capability: <");
		for (Capability c: h.getCapabilities().getCapabilityList())
			System.out.print(c.toString()+", ");
		System.out.println(">");

		System.out.print("  Suitable Implementation: {");

		for (PSAList l: h.getSuitableImplementation().getSubitableImplementation()){
			System.out.print("(");
			for (PSA p: l.getPsa()){
				System.out.print(p.getName()+", ");

			}
			System.out.print("),  ");
		}
		System.out.println("}");
	}

	public static void printPSA (PSA p){
		System.out.print("  -"+p.getName()+ " ("+ p.getPSACharacteristic().getCost()+","+ p.getPSACharacteristic().getLatency()+","+ p.getPSACharacteristic().getRating()+ ")");
		System.out.print(" <");
		for (Capability c: p.getCapability().getCapabilityList())
			System.out.print(c.toString()+", ");
		System.out.println(">");

	}



	public static void capabilityMapping(Hspl h){
		//System.out.println("Step 1: Capability Mapping in to HSPL");
		h.setCandidates(new Candidates());

		KieSession kieSession = null;
		try {
		    //--
			//kieSession = Useful.build("/refinement/rules/HSPL_rules.drl","src/main/resources/HSPL_rules.drl");
		    File temp = File.createTempFile("HSPL_rules", ".drl");
            kieSession = Useful.build("/rules/HSPL_rules.drl", "src/main/resources/HSPL_rules.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kieSession.insert(h);
		kieSession.fireAllRules();

	//	printHSPL(h);

	}
	public static void suitablePSA (Hspl h, Mapping map){
		//System.out.println("Step 2: Selection of suitable PSA for capability");
		KieSession kieSession=null;
		try {
		    //--
			//kieSession = Useful.build("/refinement/rules/PSA_rules.drl","src/main/resources/PSA_rules.drl");
		    File temp = File.createTempFile("PSA_rules", ".drl");
            kieSession = Useful.build("/rules/PSA_rules.drl", "src/main/resources/PSA_rules.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kieSession.insert(h);

		for (Capability c: Capability.values())
			kieSession.insert(c);

		for(SuitablePSA s:h.getCandidates().getSuitablePSAList() )
			kieSession.insert(s);

		for( PSA p: map.getPsaList().getPsa())
			kieSession.insert(p);

		kieSession.fireAllRules();
		//printHSPL(h);
	}
	public static void nonEnforceability_Capability(Hspl h,  Mapping map){
		//System.out.println("Step 3: Non-Enforceability");
		h.setEnforzability(true);
		CapabilityList nonEnforzableCapability= new CapabilityList();
		h.setNonEnforzableCapability(nonEnforzableCapability);

		KieSession kieSession=null;
		try {
		    //--
			//kieSession = Useful.build("/refinement/rules/earlyNonEnforzability_rules.drl","src/main/resources/earlyNonEnforzability_rules.drl");
		    File temp = File.createTempFile("earlyNonEnforzability_rules", ".drl");
            kieSession = Useful.build("/rules/earlyNonEnforzability_rules.drl", "src/main/resources/earlyNonEnforzability_rules.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kieSession.insert(h);

		for (Capability c: Capability.values())
			kieSession.insert(c);

		for(SuitablePSA s:h.getCandidates().getSuitablePSAList() )
			kieSession.insert(s);

		kieSession.fireAllRules();

		printHSPL(h);

		if(!h.isEnforzability()){
		map.setIsEnforciability(false);


			System.out.println(h.getId()+" is non-enforceable.");
			Remediationt r;

			for(Capability c: h.getNonEnforzableCapability().getCapabilityList()){
				System.out.println("- For "+c);
				System.out.print("	-PSA suggested form Repository: <");


			//Remediation from User PSA
				r=new Remediationt();
				r.setHspl(h);
				r.setSuitablePSA(new SuitablePSA());
				r.getSuitablePSA().setCapability(c);
				r.getSuitablePSA().setPsaList(new PSAList());
				for(PSA p: map.getUserPsaList().getPsa()){
					if(p.getCapability().getCapabilityList().contains(c)){
						r.getSuitablePSA().getPsaList().getPsa().add(p);
						System.out.print(p.getName()+", ");
					}
				}
				System.out.println(">");

				if(!r.getSuitablePSA().getPsaList().getPsa().isEmpty()){

					if(map.getRemediation()==null){
						map.setRemediation(new RemediationList());
					}
					map.getRemediation().getSolutionRepository().add(r);
				}

				System.out.print("	-PSA suggested form Market Place: <");

				//Remediation from Market
				r=new Remediationt();
				r.setHspl(h);
				r.setSuitablePSA(new SuitablePSA());
				r.getSuitablePSA().setCapability(c);
				r.getSuitablePSA().setPsaList(new PSAList());

				for(PSA p: map.getAdditionalPsaList().getPsa()){
					if(p.getCapability().getCapabilityList().contains(c)){
						r.getSuitablePSA().getPsaList().getPsa().add(p);
						System.out.print(p.getName()+", ");
					}
				}
				System.out.println(">");

				if(!r.getSuitablePSA().getPsaList().getPsa().isEmpty()){

					if(map.getRemediation()==null){
						map.setRemediation(new RemediationList());
					}
					map.getRemediation().getSolutionMarket().add(r);
				}



			}
		}
	}



	public static void nonEnforceability_Capability(MSPL m, Mapping map){
		//System.out.println("Step 3: Non-Enforceability");
		m.setEnforzability(true);
		CapabilityList nonEnforzableCapability= new CapabilityList();
		m.setNonEnforzableCapability(nonEnforzableCapability);

		KieSession kieSession=null;
		try {
		    //--
			//kieSession = Useful.build("/refinement/rules/earlyNonEnforzability_rules.drl","src/main/resources/earlyNonEnforzability_rules.drl");
		    File temp = File.createTempFile("earlyNonEnforzability_rules", ".drl");
            kieSession = Useful.build("/rules/earlyNonEnforzability_rules.drl","src/main/resources/earlyNonEnforzability_rules.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kieSession.insert(m);

		for (Capability c: Capability.values())
			kieSession.insert(c);

		for(SuitablePSA s:m.getCandidates().getSuitablePSAList() )
			kieSession.insert(s);

		kieSession.fireAllRules();



		if(!m.isEnforzability()){
			map.setIsEnforciability(false);


			System.out.println(m.getId()+" is non-enforceable.");
			Remediationt r;

			for(Capability c: m.getNonEnforzableCapability().getCapabilityList()){
				System.out.println("- For "+c);
				System.out.print("	-PSA suggested form Repository: <");


			//Remediation from User PSA
				r=new Remediationt();
				r.setMspl(m);
				r.setSuitablePSA(new SuitablePSA());
				r.getSuitablePSA().setCapability(c);
				r.getSuitablePSA().setPsaList(new PSAList());
				for(PSA p: map.getUserPsaList().getPsa()){
					if(p.getCapability().getCapabilityList().contains(c)){
						r.getSuitablePSA().getPsaList().getPsa().add(p);
						System.out.print(p.getName()+", ");
					}
				}
				System.out.println(">");

				if(!r.getSuitablePSA().getPsaList().getPsa().isEmpty()){

					if(map.getRemediation()==null){
						map.setRemediation(new RemediationList());
					}
					map.getRemediation().getSolutionRepository().add(r);
				}

				System.out.print("	-PSA suggested form Market Place: <");

				//Remediation from Market
				r=new Remediationt();
				r.setMspl(m);
				r.setSuitablePSA(new SuitablePSA());
				r.getSuitablePSA().setCapability(c);
				r.getSuitablePSA().setPsaList(new PSAList());

				for(PSA p: map.getAdditionalPsaList().getPsa()){
					if(p.getCapability().getCapabilityList().contains(c)){
						r.getSuitablePSA().getPsaList().getPsa().add(p);
						System.out.print(p.getName()+", ");
					}
				}
				System.out.println(">");

				if(!r.getSuitablePSA().getPsaList().getPsa().isEmpty()){

					if(map.getRemediation()==null){
						map.setRemediation(new RemediationList());
					}
					map.getRemediation().getSolutionMarket().add(r);
				}



			}
			//System.exit(-1);

		}
	}




	public static void suitableImplementation(Hspl h){
		SuitableImplementationList si=h.getSuitableImplementation();
		si.getSubitableImplementation().add(new PSAList());

		for(SuitablePSA sp: h.getCandidates().getSuitablePSAList()){
			List<PSAList> l_tmp = new Stack<PSAList>();

			for(PSAList l:si.getSubitableImplementation()){
				for(PSA p: sp.getPsaList().getPsa()){
					PSAList l_new= new PSAList();
					l_new.getPsa().addAll(l.getPsa());
					l_new.getPsa().add(p);
					l_tmp.add(l_new);

				}

			}

			si.getSubitableImplementation().clear();
			si.getSubitableImplementation().addAll(l_tmp);

		}

		SuitableImplementationList si_new=new SuitableImplementationList();
		PSAList l_dest;
		for (PSAList l: si.getSubitableImplementation()){

			l_dest=new PSAList();
			for (PSA p: l.getPsa()){
				if(!l_dest.getPsa().contains(p))
					l_dest.getPsa().add(p);
			}

			si_new.getSubitableImplementation().add(l_dest);

		}
		h.setSuitableImplementation(si_new);
	}


	public static void suitableImplementation(MSPL m){
		m.setSuitableImplementation(new SuitableImplementationList());
		SuitableImplementationList si=m.getSuitableImplementation();
		si.getSubitableImplementation().add(new PSAList());

		for(SuitablePSA sp: m.getCandidates().getSuitablePSAList()){
			List<PSAList> l_tmp = new Stack<PSAList>();

			for(PSAList l:si.getSubitableImplementation()){
				for(PSA p: sp.getPsaList().getPsa()){
					PSAList l_new= new PSAList();
					l_new.getPsa().addAll(l.getPsa());
					l_new.getPsa().add(p);
					l_tmp.add(l_new);

				}

			}

			si.getSubitableImplementation().clear();
			si.getSubitableImplementation().addAll(l_tmp);

		}

		SuitableImplementationList si_new=new SuitableImplementationList();
		PSAList l_dest;
		for (PSAList l: si.getSubitableImplementation()){

			l_dest=new PSAList();
			for (PSA p: l.getPsa()){
				if(!l_dest.getPsa().contains(p))
					l_dest.getPsa().add(p);
			}

			si_new.getSubitableImplementation().add(l_dest);

		}
		m.setSuitableImplementation(si_new);
	}


	public static void suitablePSA (MSPL m, Mapping map){
		KieSession kieSession=null;
		try {
		    //--
			//kieSession = Useful.build("/refinement/rules/PSA_rules_MSPL.drl","src/main/resources/PSA_rules_MSPL.drl");
		    File temp = File.createTempFile("PSA_rules_MSPL", ".drl");
            kieSession = Useful.build("/rules/PSA_rules_MSPL.drl", "src/main/resources/PSA_rules_MSPL.drl");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kieSession.insert(m);

		for (Capability c: Capability.values())
			kieSession.insert(c);

		for(SuitablePSA s:m.getCandidates().getSuitablePSAList() )
			kieSession.insert(s);

		for( PSA p: map.getPsaList().getPsa())
			kieSession.insert(p);

		kieSession.fireAllRules();


		//printHSPL(h);

	}


	public static void run (Mapping map, Configurations conf, Schemas schemas){
		System.out.println();
		System.out.println();
		System.out.println();
		System.out.println("Capability matching + PSA mapping");

		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL)
				||conf.getRefinementType().equals(RefinementType.POLICY_MSPL)){

			for(MSPL m: map.getMsplList().getMsplList()){
				suitablePSA(m,map);
				nonEnforceability_Capability(m, map);
				if(m.isEnforzability()){
				suitableImplementation(m);
				printMSPL(m);
				}
			}

		}
		else{

		for( Hspl h: map.getHsplList().getHspl()){
			capabilityMapping(h);
			suitablePSA(h,map);
			nonEnforceability_Capability(h, map);
			if(h.isEnforzability()){
			suitableImplementation(h);
			printHSPL2(h);
			}

		}
	}

		if(!map.isIsEnforciability()){
			 Mapping map_remediation= new Mapping();
			 map_remediation.setRemediation(map.getRemediation());
				Useful.mashal(map_remediation, conf.getRemediationFile(), Mapping.class);


			System.exit(-1);
		}

	}


	public static void run (Configuration conf){
		System.out.println();
		System.out.println();
		System.out.println();
		System.out.println("Capability matching + PSA mapping");




		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL) ||conf.getRefinementType().equals(RefinementType.POLICY_MSPL) ){

			for(MSPL m: conf.getMap().getMsplList().getMsplList()){
				suitablePSA(m,conf.getMap());
				nonEnforceability_Capability(m, conf.getMap());
				if(m.isEnforzability()){
				suitableImplementation(m);
				printMSPL(m);
				}
			}

		}
		else{

		for( Hspl h: conf.getMap().getHsplList().getHspl()){
			capabilityMapping(h);
			suitablePSA(h,conf.getMap());
			nonEnforceability_Capability(h, conf.getMap());
			if(h.isEnforzability()){
			suitableImplementation(h);
			printHSPL2(h);
			}

		}
	}

		if(!conf.getMap().isIsEnforciability()){
			 Mapping map_remediation= new Mapping();
			 map_remediation.setRemediation(conf.getMap().getRemediation());
			//System.exit(-1);
		}



	}
}