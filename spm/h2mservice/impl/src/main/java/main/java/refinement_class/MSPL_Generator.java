package main.java.refinement_class;

import main.java.hspl_class.Action;
import main.java.hspl_class.Capability;
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
import main.java.hspl_class.TimeHour;
import main.java.hspl_class.TimeInterval;
import main.java.hspl_class.WeekDay;
import main.java.mspl_class.LevelType;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import org.codehaus.plexus.util.FileUtils;

import main.java.schemaFile_class.Schemas;
import main.java.configuration_class.Configurations;
import main.java.configuration_class.RefinementType;
import main.java.matching_class.Couple;
import main.java.matching_class.HsplID;
import main.java.matching_class.Matching;
import main.java.mspl_class.ActionParameters;
import main.java.mspl_class.AnonimityAction;
import main.java.mspl_class.AntiMalwareAction;
import main.java.mspl_class.AntiMalwareCondition;
import main.java.mspl_class.ApplicationLayerCondition;
import main.java.mspl_class.Authentication;
import main.java.mspl_class.AuthenticationParameters;
import main.java.mspl_class.Confidentiality;
import main.java.mspl_class.ConfigurationRule;
import main.java.mspl_class.DataProtectionAction;
import main.java.mspl_class.DataProtectionCondition;
import main.java.mspl_class.EnableAction;
import main.java.mspl_class.EnableActionType;
import main.java.mspl_class.EventCondition;
import main.java.mspl_class.FMR;
import main.java.mspl_class.FileSystemCondition;
import main.java.mspl_class.FilteringAction;
import main.java.mspl_class.FilteringConfigurationCondition;
import main.java.mspl_class.HSPL;
import main.java.mspl_class.ICRA;
import main.java.mspl_class.IKETechnologyParameter;
import main.java.mspl_class.IPsecTechnologyParameter;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.Integrity;
import main.java.mspl_class.LoggingAction;
import main.java.mspl_class.LoggingCondition;
import main.java.mspl_class.PacketFilterCondition;
import main.java.mspl_class.ParentalControlAction;
import main.java.mspl_class.Pics;
import main.java.mspl_class.Priority;
import main.java.mspl_class.RSAC;
import main.java.mspl_class.ReduceBandwidthAction;
import main.java.mspl_class.ReduceBandwidthActionType;
import main.java.mspl_class.ReencryptNetworkConfiguration;
import main.java.mspl_class.RemoteAccessNetworkConfiguration;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.SafeNet;
import main.java.mspl_class.TLSSSLTechnologyParameter;
import main.java.mspl_class.TechnologySpecificParameters;
import main.java.mspl_class.TimeCondition;
import main.java.mspl_class.Vancouver;
import main.java.associationList_class.Association;
import main.java.associationList_class.AssociationList;
import main.java.associationList_class.Event;
import main.java.associationList_class.IP;
import main.java.associationList_class.MimeType;
import main.java.associationList_class.RE;
import main.java.associationList_class.URI;

public class MSPL_Generator {

	public static String getHSPL(Hspl h){

		String result="";

		result+=h.getSubject()+" "+ h.getAction().toString().toLowerCase()+ " " + h.getObjectH().toString().toLowerCase()+" ";

		if(h.getFields()!=null){
			Fields f = h.getFields();
			if(f.getUplinkBandwidthValue()!=null)
				result+= f.getUplinkBandwidthValue()+" ";
			
			if(f.getDownlinkBandwidthValue()!=null)
				result+= f.getDownlinkBandwidthValue()+" ";
		
			if(f.getResourceValues()!=null){
				//System.out.print("--Resurce: ");

				for(String i : f.getResourceValues().getNameResurces())
					result+=i+", ";

				result+=" ";

			}

			if(f.getPurpose()!=null){

				//System.out.print("--Purpose: ");

				for(String i : f.getPurpose().getPurposeName())
					result+=i+", ";

				result+=" ";

			}


			if(f.getSpecificURL()!=null){
				//System.out.print("--URL: ");
				result+="on ";

				for(String i : f.getSpecificURL().getURL())
					result+=i+", ";

				result+=" ";

			}


			if(f.getTypeContent()!=null){
				//System.out.print("--TypeContent: ");

				for(String i : f.getTypeContent().getContentName())
					result+=i+", ";

				result+=" ";

			}


			if(f.getTrafficTarget()!=null){
				//System.out.print("--TrafficTarget: ");

				for(String i : f.getTrafficTarget().getTargetName())
					result+=i+", ";

				result+=" ";

			}

			if(f.getTimePeriod()!=null){
				//System.out.print("--Time Period: ");

				for(TimeInterval i : f.getTimePeriod().getIntervalTime()){
					result+= "in (";

					if(i.getWeekDay()!=null)
						result+="{ ";

					for(WeekDay d:i.getWeekDay()){
						result+=d.toString()+", ";						
					}
					result+="}";
					if(i.getTimeHours()!=null){
						result+="{ ";
						for(TimeHour hour: i.getTimeHours()){
							result+= hour.getStartTime()+"-"+hour.getEndTime()+", ";

						}
						result+="} ";
					}
					result+= f.getTimePeriod().getTimeZone()+ ")";


				}

			}

		}
		return result;

	}



	public static void getMSPL(Mapping map, HashSet<ITResource> itResource_list, Matching matc, AssociationList subjects, AssociationList content, AssociationList target ){

		HSPLList hspl_list=map.getHsplList();
		//PSAList psa_list=map.getSolution().getSolutions().get(0).getPsaList();
		PSAList psa_list=new PSAList();

		for(Service s: map.getServiceGraph().getService()){
			psa_list.getPsa().add(s.getPSA());
		}

		Couple c;
		ITResource itResource;
		RuleSetConfiguration conf;
		int i;
		UUID mspl_nam;
		HsplID h_id;
		MSPLList m_list;
		MSPL m;
		for (PSA p: psa_list.getPsa()){
			i=0;
			mspl_nam=UUID.randomUUID();
			itResource= new ITResource();
			m_list=new MSPLList();
			m=new MSPL();
			m.setId("MSPL_"+mspl_nam);
			m_list.getMsplList().add(m);
			p.setMSPLList(m_list);

			itResource.setID("MSPL_"+mspl_nam);
			conf = new RuleSetConfiguration();
			itResource.setConfiguration(conf);
			conf.setName("MSPL_"+mspl_nam);
			c=new Couple();
			c.setMSPL("MSPL_"+mspl_nam);
			c.setPSA(p.getName());

			for (Hspl h: hspl_list.getHspl()){

				h_id=new HsplID();


				if (h.getImplementation().getPsa().contains(p)){
					h_id.setHspl(h.getId());
					c.getHSPLID().add(h_id);

					setMSPLConfiguration(h,p, conf,subjects,content, target, i);
					i++;
				}

			}

			matc.getCouple().add(c);
			itResource_list.add(itResource);
		}
	}




	public static void getMSPL(Mapping map, Matching matc, Configurations conf) {

		File folder = new File(conf.getMsplDirInput());
		File[] listOfFiles = folder.listFiles();

		for(File f: listOfFiles){
			try {
				FileUtils.copyFileToDirectory(f.getPath(), conf.getMsplDirOutput());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}



		PSAList psa_list=map.getSolution().getSolutions().get(0).getPsaList();
		Couple c=null;
		for (PSA p: psa_list.getPsa()){
			for(MSPL m: map.getMsplList().getMsplList()){

				if(m.getImplementation().getPsa().contains(p)){
					c=new Couple();
					c.setPSA(p.getName());
					c.setMSPL(m.getId());
				}

			}
			matc.getCouple().add(c);
		}





	}


	public static void getMSPL(Mapping map, Matching matc){

		Couple c;
		MSPLList m_list;
		MSPL m_new;

		//	MSPLList mspl_list=new MSPLList();
		//		mspl_list.getMsplList().addAll(map.getMsplList().getMsplList());	

		HashMap<String, MSPL> map_mspl=new HashMap<String, MSPL>();
		for(MSPL m: map.getMsplList().getMsplList()){
			map_mspl.put(m.getId(), m);
		}


		//	PSAList psa_list=map.getSolution().getSolutions().get(0).getPsaList();
		PSAList psa_list=new PSAList();

		for(Service s: map.getServiceGraph().getService()){


			if(s.getMSPLID()!=null){
				m_list=new MSPLList();
				s.getPSA().setMSPLList(m_list);
				m_new=new MSPL();
				m_new.setId(s.getMSPLID());
				m_list.getMsplList().add(m_new);			
				map_mspl.remove(s.getMSPLID());	

			}else{

				psa_list.getPsa().add(s.getPSA());
				if(s.getPSA().getMSPLList()!=null)
					for(MSPL m: s.getPSA().getMSPLList().getMsplList()){
						map_mspl.remove(m.getId());

					}
			}




		}




		for (PSA p: psa_list.getPsa()){
			c=new Couple();
			c.setPSA(p.getName());

			if(p.getMSPLList()==null){
				m_list=new MSPLList();
				p.setMSPLList(m_list);
			}
			else{
				m_list=p.getMSPLList();
			}


			for (MSPL m: map_mspl.values()){
				if (m.getImplementation().getPsa().contains(p)){
					c.setMSPL(m.getId());
					m_new=new MSPL();
					m_new.setId(m.getId());
					m_list.getMsplList().add(m_new);

				}
			}
			matc.getCouple().add(c);
		}
	}



	//switch MSPL 
	public static void setMSPLConfiguration (Hspl h, PSA p,RuleSetConfiguration conf, AssociationList subjects, AssociationList content, AssociationList target,  int i){
		//filtering action
				if(     ( h.getAction().equals(Action.AUTHORISE_ACCESS)|| h.getAction().equals(Action.NO_AUTHORISE_ACCESS))  && 
						( p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_4) ||
								p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_7))) 

					setMSPLConfiguration_Filtering(h,p,conf,subjects,content, target, i);

				//Enable action
				else if(h.getAction().equals(Action.ENABLE)&&  h.getObjectH().equals(ObjectH.ANTI_PHISHING) && p.getCapability().getCapabilityList().contains(Capability.ANTI_PHISHING))
					setMSPLConfiguration_EnableAntiPhishing(h,p, conf,i); 

				else if(h.getAction().equals(Action.ENABLE)&&  h.getObjectH().equals(ObjectH.ANONIMITY) && p.getCapability().getCapabilityList().contains(Capability.ANONIMITY))
					setMSPLConfiguration_EnableAnonimity(h,p, conf,i); 

				else if(h.getAction().equals(Action.ENABLE)&& h.getObjectH().equals(ObjectH.ADVANCE_PARENTAL_CONTROL) &&  p.getCapability().getCapabilityList().contains(Capability.ADVANCED_PARENTAL_CONTROL)   )
						setMSPLAdvancePC(h,p,conf,subjects,content, target, i);

				else if(h.getAction().equals(Action.ENABLE)&&  h.getObjectH().equals(ObjectH.MALWARE_DETECTION))
					setMSPL_MALWARE_DETECTION(h,p,conf,subjects,content, target, i);
				
				else if(h.getAction().equals(Action.ENABLE)&&  h.getObjectH().equals(ObjectH.LOGGING))
					setMSPL_LOGGING(h,p,conf,subjects,content, target, i); 

				
				//protection
				else if(h.getAction().equals(Action.PROT_CONF)||h.getAction().equals(Action.PROT_INTEGR)||h.getAction().equals(Action.PROT_CONF_INTEGR) )
					setMSPLConfiguration_Protection(h,p,conf,subjects,content, target, i);


				//remove
				else if(h.getAction().equals(Action.REMOVE)&& h.getObjectH().equals(ObjectH.ADVERTISEMENT))
					setMSPLRemoveAdv(h,p,conf,subjects,content, target, i);

				else if(h.getObjectH().equals(ObjectH.BANDWIDTH))
					setMSPLReduceBandwidth(h,p, conf,i); 

		//insert Capability in MSPL
		HashSet<Capability>c_list=new HashSet();
		c_list.addAll(h.getCapabilities().getCapabilityList());
		c_list.retainAll(p.getCapability().getCapabilityList());
		main.java.mspl_class.Capability cap;
		boolean flag;
		for(Capability c: c_list){
			cap=new main.java.mspl_class.Capability();
			cap.setName(main.java.mspl_class.CapabilityType.valueOf(c.toString()));
			flag=false;

			for (main.java.mspl_class.Capability conf_cap: conf.getCapability())
				if(conf_cap.getName().equals(cap.getName())){
					flag=true;
					break;
				}

			if(!flag)
				conf.getCapability().add(cap);
		}

	}	

	public static void setMSPLConfiguration_EnableAnonimity(Hspl h, PSA p,
			RuleSetConfiguration conf, int i) {
		AnonimityAction a=new AnonimityAction();
		EnableActionType at=new EnableActionType();
		at.setEnable(true);
		at.setObjectToEnable("ANONIMITY");
		a.setEnableActionType(at);
		a.getCountry().add(h.getFields().getCountry());
		
		//conf.setDefaultAction(a);
		
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		
		rule.setConfigurationRuleAction(a);
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);		
		
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		
	}



	public static void setMSPLConfiguration_EnableAntiPhishing(Hspl h, PSA p,
			RuleSetConfiguration conf, int i) {
		
		EnableAction a=new EnableAction();
		EnableActionType at=new EnableActionType();
		at.setEnable(true);
		at.setObjectToEnable("ANTI_PHISHING");
		a.setEnableActionType(at);
		conf.setDefaultAction(a);
		
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);		
		
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
	}



	public static void setMSPLReduceBandwidth(Hspl h, PSA p,RuleSetConfiguration conf, int i) {
		ReduceBandwidthAction a=new ReduceBandwidthAction();
		a.setReduceBandwidthActionType(new ReduceBandwidthActionType());
		if(h.getFields().getUplinkBandwidthValue()!=null)
		a.getReduceBandwidthActionType().setUplinkBandwidthValue(h.getFields().getUplinkBandwidthValue());
		
		if(h.getFields().getDownlinkBandwidthValue()!=null)
			a.getReduceBandwidthActionType().setDownlinkBandwidthValue(h.getFields().getDownlinkBandwidthValue());
			
		conf.setDefaultAction(a);
		
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);		
		
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		
	}

public static void setMSPL_LOGGING(Hspl h, PSA p, RuleSetConfiguration conf, AssociationList subjects, AssociationList content, AssociationList target, int i) {
		
	HashMap<String, Association> contet_map=new HashMap<String, Association>();
	HashMap<String, Association> target_map=new HashMap<String, Association>();


	//content-> propose
	for(Association l: content.getAssociations()){
		contet_map.put(l.getName(),l);
	}

	//target-> target
	for(Association l: target.getAssociations()){
		target_map.put(l.getName(),l);
	}



	LoggingAction a=new LoggingAction();
	a.setLoggingActionType("log_connection");
	conf.setDefaultAction(a);

	ConfigurationRule rule=new ConfigurationRule();
	HSPL h_string=new HSPL();
	h_string.setHSPLId(h.getId());
	h_string.setHSPLText(getHSPL(h));
	rule.getHSPL().add(h_string);

	LoggingCondition lc=new LoggingCondition();


	EventCondition ec; //
	PacketFilterCondition pc =new PacketFilterCondition();
	ApplicationLayerCondition app= new ApplicationLayerCondition();
	String url="";
	String ips="";

	Association as;
	if(h.getFields().getPurpose()!=null)
		for (String s:h.getFields().getPurpose().getPurposeName()){
			as=contet_map.get(s);
			if(as!=null)
				for(Event e: as.getEvent()){
					ec=new EventCondition();
					ec.setEvents(e.getEventsName().get(0));
					ec.setInterval(e.getInterval().get(0));
					ec.setThreshold(e.getThreshold().get(0));
					lc.setEventCondition(ec);
				}	
		}

	if( h.getFields().getTrafficTarget()!=null){
		for (String s: h.getFields().getTrafficTarget().getTargetName()){

			as=target_map.get(s);
			if(as!=null)
				for(IP ip:as.getIP()){
					ips+=ip.getIpValue()+",";
				}
		}
		pc.setDestinationAddress(ips);	
	}


	if(h.getFields().getSpecificURL()!=null){
		for(String s: h.getFields().getSpecificURL().getURL()){
			url+=s+",";
		}
		app.setURL(url);

	}


	if(h.getFields().getTypeContent()!=null){
		for (String s: h.getFields().getTypeContent().getContentName()){

			as=contet_map.get(s);
			if(as!=null)
				for(URI u:as.getURI()){
					url+=u.getURIValue()+",";
				}
		}
		app.setURL(url);

	}

	if(!url.equals(""))			
		lc.getApplicationCondition().add(app);

	if(!ips.equals(""))
		lc.getPacketCondition().add(pc);

	rule.setConfigurationCondition(lc);


	rule.setIsCNF(false);
	Priority ed1 = new Priority();
	ed1.setValue(BigInteger.valueOf(i));
	rule.setExternalData(ed1);
	rule.setName("Rule"+i);
	i++;
	conf.getConfigurationRule().add(rule);		

	//Resolution Strategy
	FMR fmr = new FMR();
	conf.setResolutionStrategy(fmr);
	}



	public static void setMSPL_MALWARE_DETECTION(Hspl h, PSA p,
			RuleSetConfiguration conf, AssociationList subjects, AssociationList content, AssociationList target, int i) {
		
		//mspl_class.
		HashMap<String, Association> contet_map=new HashMap<String, Association>();
		HashMap<String, Association> target_map=new HashMap<String, Association>();


		//content-> propose
		for(Association l: content.getAssociations()){
			contet_map.put(l.getName(),l);
		}

		//target-> target
		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}
		
		
		AntiMalwareAction a=new AntiMalwareAction();
		a.setAntiMalwareActionType("");
		conf.setDefaultAction(a);
		
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		
		AntiMalwareCondition ac	=new AntiMalwareCondition();
		EventCondition ec; //
		ApplicationLayerCondition ap=new ApplicationLayerCondition();
		FileSystemCondition fc=new FileSystemCondition();
		
		Association as;
		if(h.getFields().getPurpose()!=null)
			for (String s:h.getFields().getPurpose().getPurposeName()){
					as=contet_map.get(s);
					if(as!=null)
					for(Event e: as.getEvent()){
						ec=new EventCondition();
						ec.setEvents(e.getEventsName().get(0));
						ec.setInterval(e.getInterval().get(0));
						ec.setThreshold(e.getThreshold().get(0));
						ac.setEventCondition(ec);
					}	
			}
		
		if(h.getFields().getTypeContent()!=null){
			String mime="";
			
			for(String s: h.getFields().getTypeContent().getContentName()){
					as=contet_map.get(s);
					if(as!=null)
					for(MimeType m: as.getMimeType()){
						mime+=m.getMimeTypeValue()+",";
					}
				
			}
			ap.setMimeType(mime);
		}
		ac.setApplicationLayerCondition(ap);
		
		rule.setConfigurationCondition(ac);
		
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);		
		
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		
	}


	public static void setMSPLAdvancePC(Hspl h, PSA p,RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, AssociationList target, int i) {


		ParentalControlAction pa=new ParentalControlAction();
		
		//EnableAction a=new EnableAction();
		EnableActionType at=new EnableActionType();
		at.setEnable(true);
		at.setObjectToEnable(p.getName());
		pa.setEnableActionType(at);
		
		Pics pics=new Pics();
		
		if(h.getFields().getTypeContent()==null || h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("adolescent")){
			pics.setCyberNOTsex(3);
			pics.setEvaluWEB(1);
			pics.setWeburbia(1);

			ICRA icra=new ICRA();
			icra.setICRAchat(false);
			icra.setICRAdrugsalcohol(false);
			icra.setICRAdrugsuse(false);
			icra.setICRAlanguagesexual(false);
			icra.setICRAnuditybottoms(false);
			icra.setICRAnuditygraphic(false);
			icra.setICRAnuditytopless(false);
			icra.setICRAviolencetofantasy(false);
			pics.setICRA(icra);
			
			RSAC rsac=new RSAC();
			rsac.setRSAClanguage(2);
			rsac.setRSACnudity(2);
			rsac.setRSACsex(2);
			rsac.setRSACviolence(2);
			pics.setRSAC(rsac);
			
			SafeNet safenet= new SafeNet();
			safenet.setSafeSurfdruguse(3);
			safenet.setSafeSurfgambling(3);
			safenet.setSafeSurfheterosexualthemes(3);
			safenet.setSafeSurfhomosexualthemes(3);
			safenet.setSafeSurfotheradultthemes(3);
			safenet.setSafeSurfprofanity(3);
			safenet.setSafeSurfviolence(3);
			pics.setSafeNet(safenet);

			Vancouver vancouver=new Vancouver();
			vancouver.setVancouvereducationalcontent(0);
			vancouver.setVancouvergambling(0);
			vancouver.setVancouverprofanity(0);
			vancouver.setVancouversex(0);
			vancouver.setVancouverviolence(0);
			pics.setVancouver(vancouver);
		}
		
		else if(h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("child")){
			pics.setCyberNOTsex(0);
			pics.setEvaluWEB(0);
			pics.setWeburbia(0);

			ICRA icra=new ICRA();
			icra.setICRAchat(true);
			icra.setICRAdrugsalcohol(true);
			icra.setICRAdrugsuse(true);
			icra.setICRAlanguagesexual(true);
			icra.setICRAnuditybottoms(true);
			icra.setICRAnuditygraphic(true);
			icra.setICRAnuditytopless(true);
			icra.setICRAviolencetofantasy(true);
			pics.setICRA(icra);
			
			RSAC rsac=new RSAC();
			rsac.setRSAClanguage(0);
			rsac.setRSACnudity(0);
			rsac.setRSACsex(0);
			rsac.setRSACviolence(0);
			pics.setRSAC(rsac);
			
			SafeNet safenet= new SafeNet();
			safenet.setSafeSurfdruguse(0);
			safenet.setSafeSurfgambling(0);
			safenet.setSafeSurfheterosexualthemes(0);
			safenet.setSafeSurfhomosexualthemes(0);
			safenet.setSafeSurfotheradultthemes(0);
			safenet.setSafeSurfprofanity(0);
			safenet.setSafeSurfviolence(0);
			pics.setSafeNet(safenet);

			Vancouver vancouver=new Vancouver();
			vancouver.setVancouvereducationalcontent(0);
			vancouver.setVancouvergambling(0);
			vancouver.setVancouverprofanity(0);
			vancouver.setVancouversex(0);
			vancouver.setVancouverviolence(0);
			pics.setVancouver(vancouver);
		
		}
		
		
		else if(h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("pgr")){
			pics.setCyberNOTsex(0);
			pics.setEvaluWEB(0);
			pics.setWeburbia(0);

			ICRA icra=new ICRA();
			icra.setICRAchat(true);
			icra.setICRAdrugsalcohol(true);
			icra.setICRAdrugsuse(true);
			icra.setICRAlanguagesexual(true);
			icra.setICRAnuditybottoms(true);
			icra.setICRAnuditygraphic(true);
			icra.setICRAnuditytopless(true);
			icra.setICRAviolencetofantasy(true);
			pics.setICRA(icra);
			
			RSAC rsac=new RSAC();
			rsac.setRSAClanguage(0);
			rsac.setRSACnudity(0);
			rsac.setRSACsex(0);
			rsac.setRSACviolence(0);
			pics.setRSAC(rsac);
			
			SafeNet safenet= new SafeNet();
			safenet.setSafeSurfdruguse(0);
			safenet.setSafeSurfgambling(0);
			safenet.setSafeSurfheterosexualthemes(0);
			safenet.setSafeSurfhomosexualthemes(0);
			safenet.setSafeSurfotheradultthemes(0);
			safenet.setSafeSurfprofanity(0);
			safenet.setSafeSurfviolence(0);
			pics.setSafeNet(safenet);

			Vancouver vancouver=new Vancouver();
			vancouver.setVancouvereducationalcontent(0);
			vancouver.setVancouvergambling(0);
			vancouver.setVancouverprofanity(0);
			vancouver.setVancouversex(0);
			vancouver.setVancouverviolence(0);
			pics.setVancouver(vancouver);
		
		}
		
		else if(h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("universal")){
		
			pics.setCyberNOTsex(0);
			pics.setEvaluWEB(0);
			pics.setWeburbia(0);

			ICRA icra=new ICRA();
			icra.setICRAchat(true);
			icra.setICRAdrugsalcohol(true);
			icra.setICRAdrugsuse(true);
			icra.setICRAlanguagesexual(true);
			icra.setICRAnuditybottoms(true);
			icra.setICRAnuditygraphic(true);
			icra.setICRAnuditytopless(true);
			icra.setICRAviolencetofantasy(true);
			pics.setICRA(icra);
			
			RSAC rsac=new RSAC();
			rsac.setRSAClanguage(0);
			rsac.setRSACnudity(0);
			rsac.setRSACsex(0);
			rsac.setRSACviolence(0);
			pics.setRSAC(rsac);
			
			SafeNet safenet= new SafeNet();
			safenet.setSafeSurfdruguse(0);
			safenet.setSafeSurfgambling(0);
			safenet.setSafeSurfheterosexualthemes(0);
			safenet.setSafeSurfhomosexualthemes(0);
			safenet.setSafeSurfotheradultthemes(0);
			safenet.setSafeSurfprofanity(0);
			safenet.setSafeSurfviolence(0);
			pics.setSafeNet(safenet);

			Vancouver vancouver=new Vancouver();
			vancouver.setVancouvereducationalcontent(0);
			vancouver.setVancouvergambling(0);
			vancouver.setVancouverprofanity(0);
			vancouver.setVancouversex(0);
			vancouver.setVancouverviolence(0);
			pics.setVancouver(vancouver);
		}
		
		pa.setPics(pics);
		conf.setDefaultAction(pa);
		
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);

		
//		ApplicationLayerCondition alc=new ApplicationLayerCondition();
//		
//		if(h.getFields().getTypeContent().getContentName()!=null)		
//			alc.setParentalControlLevel(LevelType.valueOf(h.getFields().getTypeContent().getContentName().get(0).toUpperCase()));
//		
//		else
//			alc.setParentalControlLevel(LevelType.PGR);
//		
//		FilteringConfigurationCondition fcc = new FilteringConfigurationCondition();
//		fcc.setApplicationLayerCondition(alc);
//		rule.setConfigurationCondition(fcc);
//		
		conf.setDefaultAction(pa);
		
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);		
		
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
	}



	public static void setMSPLRemoveAdv(Hspl h, PSA p,RuleSetConfiguration conf, AssociationList subjects, AssociationList content, AssociationList target, int i) {


		//HashMap<String, Association> contet_map=new HashMap<String, Association>();

		Association removeAdv_ass=null;


		for(Association l: content.getAssociations()){
			if (l.getName().equals("advertisement"))
				removeAdv_ass=l;
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		//HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
		HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();




		//ConfigurationRule rule1 = new ConfigurationRule();





		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";


		//		ApplicationLayerCondition (URL)

		ApplicationLayerCondition app=new ApplicationLayerCondition();
		String urls="";
		String reg="";


		for(URI s1: removeAdv_ass.getURI())
			urls+=s1.getURIValue()+",";				

		app.setURL(urls);
		//list_app.add(alc);

		for (RE re: removeAdv_ass.getRE())
			reg+=re.getReValue()+",";	

		app.setURLRegex(reg);


		ConfigurationRule rule;
		PacketFilterCondition pkt2;
		FilteringConfigurationCondition fcc; 


		pkt2=new PacketFilterCondition();
		pkt2.setSourceAddress(sourceAddress);
		fcc = new FilteringConfigurationCondition();

		fcc.setApplicationLayerCondition(app);
		fcc.setPacketFilterCondition(pkt2);

		rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		rule.setConfigurationCondition(fcc);

		rule.setConfigurationRuleAction(deny);

		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);
















	}




	public static void setMSPLConfiguration_Protection(Hspl h, PSA p, RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, AssociationList target, int i) {

		if(p.getCapability().getCapabilityList().contains(Capability.IP_SEC_PROTOCOL)){
			setMSPLCofiguration_IPSEC(h,p,conf,subjects,content, target, i);
		}
		else if(p.getCapability().getCapabilityList().contains(Capability.TLS_PROTOCOL) && !p.getCapability().getCapabilityList().contains(Capability.REENCRYPT)){
			setMSPLCofiguration_TLS(h,p,conf,subjects,content, target, i);

		}else if(p.getCapability().getCapabilityList().contains(Capability.TLS_PROTOCOL) && p.getCapability().getCapabilityList().contains(Capability.REENCRYPT)){
			setMSPLCofiguration_Reencrypt(h,p,conf,subjects,content, target, i);

		}
	}

	public static void setMSPLCofiguration_Reencrypt(Hspl h, PSA p,
			RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, AssociationList target, int i) {
		ConfigurationRule rule;
		//DataProtectionCondition data_cond= new DataProtectionCondition ();

		DataProtectionAction a=new DataProtectionAction();
		ActionParameters ap=new ActionParameters();




		TLSSSLTechnologyParameter tls_par=new TLSSSLTechnologyParameter();

		tls_par.setCiphersClient("ALL");
		tls_par.setSslVersionClient("SSLv23");
		tls_par.setCiphersServer("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK");
		tls_par.setSslVersionServer("TLSv1.2");

		ReencryptNetworkConfiguration re_par=new ReencryptNetworkConfiguration();

		if(h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("secure_web"))
			re_par.setReencryptionStrategy("BEST-EFFORT");
			
		else if(h.getFields().getTypeContent().getContentName().get(0).toLowerCase().equals("web"))
			re_par.setReencryptionStrategy("ONLY-SECURE");
			
		ap.getTechnologyParameter().add(tls_par);
		ap.setAdditionalNetworkConfigurationParameters(re_par);
		a.setTechnologyActionParameters(ap);




		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);


		rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);
		rule.setConfigurationRuleAction(a);
		//rule.setConfigurationCondition(data_cond);
		rule.setIsCNF(false);
		Priority ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);
		main.java.mspl_class.Capability cap= new main.java.mspl_class.Capability();
		cap.setName(main.java.mspl_class.CapabilityType.TLS_PROTOCOL);
		conf.getCapability().add(cap);
		cap= new main.java.mspl_class.Capability();
		cap.setName(main.java.mspl_class.CapabilityType.REENCRYPT);
		conf.getCapability().add(cap);


	}





	public  static void setMSPLCofiguration_TLS(Hspl h, PSA p,
			RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, AssociationList target, int i) {

	}

	public static void setMSPLCofiguration_IPSEC(Hspl h, PSA p,
			RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, AssociationList target, int i) {
		DataProtectionCondition data_cond;
		HashMap<String, Association> target_map=new HashMap<String, Association>();
		
		
		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}

		
		/*	if( ){
			

			}
		}
		 */	
		
		if(h.getFields().getTrafficTarget()!=null){
			int j=0;
			ConfigurationRule rule;

			DataProtectionAction a=new DataProtectionAction();
			ActionParameters ap=new ActionParameters();
			IPsecTechnologyParameter ipsec_par=new IPsecTechnologyParameter();
			ipsec_par.setIsTunnel(false);
			Association a_vpn=target_map.get(h.getFields().getTrafficTarget().getTargetName().get(0));


			/* old
			 * //sourceAddress
			String sourceAddress="";
			for (Association ass: subjects.getAssociations())
				if(h.getSubject().compareTo(ass.getName())==0)			
					for(IP ip: ass.getIP()){
						if(j==0){
							sourceAddress+=ip.getIpValue();
							j++;

						}
						else
							sourceAddress+=","+ip.getIpValue();

					}
			j=0;






			//String destAddress
			String destAddress="";
			String s=h.getFields().getTrafficTarget().getTargetName().get(0);
			

			for(IP ip: target_map.get(s).getIP()){
				if(j==0){
					destAddress+=ip.getIpValue();
					j++;
				}
				else
					destAddress+=","+ip.getIpValue();

			}

			j=0;

			
			
			ipsec_par.setLocalEndpoint(sourceAddress);
			ipsec_par.setRemoteEndpoint(destAddress);
*/
						
			ipsec_par.setLocalEndpoint(a_vpn.getVPN().get(0).getLocalEndpoint());
			ipsec_par.setRemoteEndpoint(a_vpn.getVPN().get(0).getRemoteEndpint());

			IKETechnologyParameter ike_par=new IKETechnologyParameter();
			ike_par.setESN(false);
			ike_par.setLifetime("60m");
			ike_par.setRekeyMargin("3m");
			ike_par.setKeyringTries("3");
			ike_par.setExchangeMode("ikev2");
			ike_par.setEncryptionAlgorithm("aes");
			ike_par.setHashAlgorithm("sha1");
			ike_par.setPhase1DhGroup("modp1024");
			ike_par.setPhase2CompressionAlgorithm("deflate");


			RemoteAccessNetworkConfiguration rem_conf=new RemoteAccessNetworkConfiguration();

			

			/* OLD
			 * 
			 * String remote_sub="";
			 * if(h.getFields().getTrafficTarget()!=null){

				for (String s: h.getFields().getTrafficTarget().getTargetName()){
					if(target_map.containsKey(s)){
						for(IP ip: target_map.get(s).getIP()){
							if(j==0){
								remote_sub+=ip.getIpValue();

								j++;
							}
							else
								remote_sub+=","+ip.getIpValue();

						}


					}
				}

				j=0;
				rem_conf.setRemoteSubnet(remote_sub);

			}
			else{
				remote_sub="0.0.0.0/0";
				rem_conf.setRemoteSubnet(remote_sub);

			}*/
			rem_conf.setRemoteSubnet(a_vpn.getVPN().get(0).getRemoteSubNet());
			rem_conf.setLocalSubnet(a_vpn.getVPN().get(0).getLocalSubNet());
			rem_conf.setStartIPAddress("");
			

			
			AuthenticationParameters aut_par = new AuthenticationParameters();

			aut_par.setPsKeyValue(a_vpn.getVPN().get(0).getAutentication().getCert().getPsKeyValue());
			aut_par.setRemoteId(a_vpn.getVPN().get(0).getAutentication().getCert().getRemoteId());
			aut_par.setCertId(a_vpn.getVPN().get(0).getAutentication().getCert().getCertId());
			aut_par.setCertFilename(a_vpn.getVPN().get(0).getAutentication().getCert().getCertFilename());
			

			if(p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY) ){
				a.setTechnology("ipsec_ESP");
				ipsec_par.setIPsecProtocol("ESP");

				Confidentiality conf_prop=new Confidentiality();
				conf_prop.setEncryptionAlgorithm("AES");
				conf_prop.setKeySize("256");
				conf_prop.setMode("CBC");

				Integrity int_prop= new Integrity();
				int_prop.setIntegrityAlgorithm("sha1");


				a.getTechnologyActionSecurityProperty().add(conf_prop);
				a.getTechnologyActionSecurityProperty().add(int_prop);


			}

			else if(!p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY)){
				a.setTechnology("ipsec_AH");
				ipsec_par.setIPsecProtocol("AH");
				Integrity int_prop= new Integrity();
				int_prop.setIntegrityAlgorithm("sha1");
				a.getTechnologyActionSecurityProperty().add(int_prop);

			}

			else if(p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && !p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY)){
				a.setTechnology("ipsec_ESP");
				ipsec_par.setIPsecProtocol("ESP");
				Confidentiality conf_prop=new Confidentiality();
				conf_prop.setEncryptionAlgorithm("AES");
				conf_prop.setKeySize("256");
				conf_prop.setMode("CBC");
				a.getTechnologyActionSecurityProperty().add(conf_prop);


			}

			Authentication aut_prop= new Authentication();
			aut_prop.setPeerAuthenticationMechanism("preshared_key");
			a.getTechnologyActionSecurityProperty().add(aut_prop);

			data_cond= new DataProtectionCondition ();


			ap.setAdditionalNetworkConfigurationParameters(rem_conf);

			ap.getTechnologyParameter().add(ipsec_par);
			ap.getTechnologyParameter().add(ike_par);
			ap.setAuthenticationParameters(aut_par);
			a.setTechnologyActionParameters(ap);

			//Resolution Strategy
			FMR fmr = new FMR();
			conf.setResolutionStrategy(fmr);


			rule=new ConfigurationRule();
			HSPL h_string=new HSPL();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationRuleAction(a);
			rule.setConfigurationCondition(data_cond);
			rule.setIsCNF(false);
			Priority ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);

			main.java.mspl_class.Capability cap=new main.java.mspl_class.Capability();
			cap.setName(main.java.mspl_class.CapabilityType.IP_SEC_PROTOCOL);
			//Capability.IP_SEC_PROTOCOL;
			if(!conf.getCapability().contains(cap))
				conf.getCapability().add(cap);

		}

		else if(h.getFields().getTrafficTarget()==null ||target_map.containsKey("default_gateway")){
			int j=0;
			ConfigurationRule rule;

			DataProtectionAction a=new DataProtectionAction();
			ActionParameters ap=new ActionParameters();
			IPsecTechnologyParameter ipsec_par=new IPsecTechnologyParameter();
			ipsec_par.setIsTunnel(false);


			//sourceAddress
			String sourceAddress="";
			for (Association ass: subjects.getAssociations())
				if(h.getSubject().compareTo(ass.getName())==0)			
					for(IP ip: ass.getIP()){
						if(j==0){
							sourceAddress+=ip.getIpValue();
							j++;

						}
						else
							sourceAddress+=","+ip.getIpValue();

					}
			j=0;






			//String destAddress
			String destAddress="";
			for(IP ip: target_map.get("default_gateway").getIP()){
				if(j==0){
					destAddress+=ip.getIpValue();
					j++;
				}
				else
					destAddress+=","+ip.getIpValue();

			}

			j=0;

			ipsec_par.setLocalEndpoint(sourceAddress);
			ipsec_par.setRemoteEndpoint(destAddress);


			IKETechnologyParameter ike_par=new IKETechnologyParameter();
			ike_par.setESN(false);
			ike_par.setExchangeMode("ikev2");
			ike_par.setEncryptionAlgorithm("aes");
			ike_par.setHashAlgorithm("sha1");
			ike_par.setPhase1DhGroup("modp1024");
			ike_par.setPhase2CompressionAlgorithm("deflate");


			RemoteAccessNetworkConfiguration rem_conf=new RemoteAccessNetworkConfiguration();

			String remote_sub="";

			if(h.getFields().getTrafficTarget()!=null){

				for (String s: h.getFields().getTrafficTarget().getTargetName()){
					if(target_map.containsKey(s)){
						for(IP ip: target_map.get(s).getIP()){
							if(j==0){
								remote_sub+=ip.getIpValue();

								j++;
							}
							else
								remote_sub+=","+ip.getIpValue();

						}


					}
				}

				j=0;
				rem_conf.setRemoteSubnet(remote_sub);

			}
			else{
				remote_sub="0.0.0.0/0";
				rem_conf.setRemoteSubnet(remote_sub);

			}
			AuthenticationParameters aut_par = new AuthenticationParameters();

			//aut.setPsKeyPath(value);
			aut_par.setPsKeyValue("mypk");


			if(p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY) ){
				a.setTechnology("ipsec_ESP");
				ipsec_par.setIPsecProtocol("ESP");

				Confidentiality conf_prop=new Confidentiality();
				conf_prop.setEncryptionAlgorithm("AES");
				conf_prop.setKeySize("256");
				conf_prop.setMode("CBC");

				Integrity int_prop= new Integrity();
				int_prop.setIntegrityAlgorithm("sha1");


				a.getTechnologyActionSecurityProperty().add(conf_prop);
				a.getTechnologyActionSecurityProperty().add(int_prop);


			}

			else if(!p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY)){
				a.setTechnology("ipsec_AH");
				ipsec_par.setIPsecProtocol("AH");
				Integrity int_prop= new Integrity();
				int_prop.setIntegrityAlgorithm("sha1");
				a.getTechnologyActionSecurityProperty().add(int_prop);

			}

			else if(p.getCapability().getCapabilityList().contains(Capability.PROTECTION_CONFIDENTIALITY) && !p.getCapability().getCapabilityList().contains(Capability.PROTECTION_INTEGRITY)){
				a.setTechnology("ipsec_ESP");
				ipsec_par.setIPsecProtocol("ESP");
				Confidentiality conf_prop=new Confidentiality();
				conf_prop.setEncryptionAlgorithm("AES");
				conf_prop.setKeySize("256");
				conf_prop.setMode("CBC");
				a.getTechnologyActionSecurityProperty().add(conf_prop);


			}

			Authentication aut_prop= new Authentication();
			aut_prop.setPeerAuthenticationMechanism("preshared_key");
			a.getTechnologyActionSecurityProperty().add(aut_prop);

			data_cond= new DataProtectionCondition ();


			ap.setAdditionalNetworkConfigurationParameters(rem_conf);

			ap.getTechnologyParameter().add(ipsec_par);
			ap.getTechnologyParameter().add(ike_par);
			ap.setAuthenticationParameters(aut_par);
			a.setTechnologyActionParameters(ap);

			//Resolution Strategy
			FMR fmr = new FMR();
			conf.setResolutionStrategy(fmr);


			rule=new ConfigurationRule();
			HSPL h_string=new HSPL();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationRuleAction(a);
			rule.setConfigurationCondition(data_cond);
			rule.setIsCNF(false);
			Priority ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);

			main.java.mspl_class.Capability cap=new main.java.mspl_class.Capability();
			cap.setName(main.java.mspl_class.CapabilityType.IP_SEC_PROTOCOL);
			//Capability.IP_SEC_PROTOCOL;
			if(!conf.getCapability().contains(cap))
				conf.getCapability().add(cap);

		}
		



	}

	public static void setMSPLConfiguration_Filtering(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects, AssociationList content, AssociationList target, int i){

		if(h.getObjectH().equals(ObjectH.INTERNET_TRAFFIC))
			setMSPLConfiguration_Filtering_Internet(h,p,conf,subjects,content, target, i);


		else if(h.getObjectH().equals(ObjectH.INTRANET_TRAFFIC)){
			setMSPLConfiguration_Filtering_Intranet(h,p,conf,subjects,content, target, i);
		}

		else if(h.getObjectH().equals(ObjectH.VO_IP_TRAFFIC) ){
			setMSPLConfiguration_Filtering_VoIP( h,  p, conf, subjects, target, i);
		}



		else if(h.getObjectH().equals(ObjectH.DNS_TRAFFIC) && h.getAction().equals(Action.NO_AUTHORISE_ACCESS)){
			setMSPLConfiguration_Filtering_DNS(h,  p, conf, subjects,   target,  i);

		}

		else if(h.getObjectH().equals(ObjectH.DNS_TRAFFIC) && h.getAction().equals(Action.AUTHORISE_ACCESS)){
			setMSPLConfiguration_Allow_DNS(h,  p, conf, subjects,  target, i);

		}

		else if(h.getObjectH().equals(ObjectH.P_2_P_TRAFFIC)){
			setMSPLConfiguration_Filtering_P2P( h,  p, conf, subjects,  content,  target,  i);
		}


		else if(h.getObjectH().equals(ObjectH.ALL_TRAFFIC) ){
			setMSPLConfiguration_Filtering_Internet(h,p,conf,subjects,content, target, i);

		}











	}




	public static void setMSPLConfiguration_Allow_DNS(Hspl h, PSA p,
			RuleSetConfiguration conf, AssociationList subjects,
			AssociationList content, int i) {

		HashMap<String, Association> contet_map=new HashMap<String, Association>();

		for(Association l: content.getAssociations()){
			contet_map.put(l.getName(),l);
		}

		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");




		/*
	 	// DefaultAction
		if(conf.getDefaultAction()==null){
			conf.setDefaultAction(allow);
		}
		 */

		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);






		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";



		String ip_dest="";

		for (String s: h.getFields().getTrafficTarget().getTargetName())
			if(contet_map.containsKey(s))
				for(IP ip: contet_map.get(s).getIP())
					ip_dest+=ip.getIpValue()+",";







		ConfigurationRule rule;
		FilteringConfigurationCondition fcc; 
		PacketFilterCondition  pkt_UDP ;

		Priority ed1;

		pkt_UDP=new PacketFilterCondition();
		pkt_UDP.setSourceAddress(sourceAddress);
		pkt_UDP.setDestinationPort("53,5353");


		if(!ip_dest.equals(""))
			pkt_UDP.setDestinationAddress(ip_dest);




		fcc = new FilteringConfigurationCondition();
		fcc.setPacketFilterCondition(pkt_UDP);

		rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);

		rule.setConfigurationCondition(fcc);
		rule.setConfigurationRuleAction(allow);


		rule.setIsCNF(false);
		ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);



		//block other DNS  

		pkt_UDP=new PacketFilterCondition();
		pkt_UDP.setSourceAddress(sourceAddress);
		pkt_UDP.setDestinationPort("53,5353");




		fcc = new FilteringConfigurationCondition();
		fcc.setPacketFilterCondition(pkt_UDP);

		rule=new ConfigurationRule();
		rule.getHSPL().add(h_string);

		rule.setConfigurationCondition(fcc);
		rule.setConfigurationRuleAction(deny);


		rule.setIsCNF(false);
		ed1 = new Priority();
		ed1.setValue(BigInteger.valueOf(i));
		rule.setExternalData(ed1);
		rule.setName("Rule"+i);
		i++;
		conf.getConfigurationRule().add(rule);



	}



	public static void setMSPLConfiguration_Filtering_Internet(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects, AssociationList content, AssociationList target, int i){


		HashMap<String, Association> contet_map=new HashMap<String, Association>();
		HashMap<String, Association> target_map=new HashMap<String, Association>();



		for(Association l: content.getAssociations()){
			contet_map.put(l.getName(),l);
		}

		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				conf.setDefaultAction(deny);
			else			
				conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
		HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();




		//ConfigurationRule rule1 = new ConfigurationRule();





		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";


		if(h.getFields().getTimePeriod()!=null || h.getFields().getSpecificURL()!=null || h.getFields().getTrafficTarget()!=null || h.getFields().getTypeContent()!=null ){
			//if(h.getFields()!=null){

			//time Conditions 
			TimeCondition time = null; 
			String hour_string;
			String week_string;

			if(h.getFields().getTimePeriod()!=null && p.getCapability().getCapabilityList().contains(Capability.TIMING)){

				for(TimeInterval t: h.getFields().getTimePeriod().getIntervalTime()){
					time= new TimeCondition();
					hour_string="";
					week_string="";


					for(TimeHour hour:t.getTimeHours()){
						//hour_string+=hour.getStartTime().toString()+"-"+hour.getEndTime().toString()+",";

						String start=hour.getStartTime().toString();
						String[] parts = start.split(":");
						start=parts[0]+":"+parts[1];
						String end= hour.getEndTime().toString();
						parts =end.split(":");
						end=parts[0]+":"+parts[1];
						hour_string+=start+"-"+end+",";


					}

					for(WeekDay w: t.getWeekDay()){
						week_string+=w.toString()+",";

					}
					time.setTime(h.getFields().getTimePeriod().getTimeZone());
					time.setTime(hour_string);
					time.setWeekday(week_string);
					list_time.add(time);
				}
			}

			//	ApplicationLayerCondition (URL)

			ApplicationLayerCondition alc;
			if(h.getFields().getSpecificURL()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_7)){
				String urls="";
				alc= new ApplicationLayerCondition();						
				for (String s: h.getFields().getSpecificURL().getURL()){


					if(contet_map.containsKey(s))
						//list of URL
						for(URI s1: contet_map.get(s).getURI())
							urls+=s1.getURIValue()+",";
					else //singol URL
						urls+=s+",";

				}
				alc.setURL(urls);

				list_app.add(alc);
			}

			//type of content 
			if(h.getFields().getTypeContent()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_7)){
				String urls="";
				String reg="";
				alc= new ApplicationLayerCondition();						

				/*for (String s: h.getFields().getTypeContent().getContentName())
					name+=s+",";

				alc.setPhrase(name);*/

				for (String s: h.getFields().getTypeContent().getContentName()){
					if(contet_map.containsKey(s)){
						//list of URL
						for(URI s1: contet_map.get(s).getURI())
							urls+=s1.getURIValue()+",";

						for (RE re: contet_map.get(s).getRE())
							reg+=re.getReValue()+",";	


					}

				}
				if(!urls.equals("") || ! reg.equals("")){

					if(!urls.equals(""))
						alc.setURL(urls);

					if(! reg.equals(""))
						alc.setURLRegex(reg);

					list_app.add(alc);

				}				

			}
			//traffic trarget
			PacketFilterCondition pkt;
			if(h.getFields().getTrafficTarget()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_4) ){
				String ip_dest="";
				pkt=new PacketFilterCondition();

				for(String s: h.getFields().getTrafficTarget().getTargetName() )
					if(target_map.containsKey(s))
						for(IP ip: target_map.get(s).getIP())
							ip_dest+=ip.getIpValue()+",";

				if(!ip_dest.equals("")){
					pkt.setDestinationAddress(ip_dest);
					pkt.setSourceAddress(sourceAddress);

					list_pfc.add(pkt);
				}
			}


			// HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
			//	HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
			//	HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();


			ConfigurationRule rule;
			PacketFilterCondition pkt2;
			FilteringConfigurationCondition fcc; 

			for(ApplicationLayerCondition app:list_app ){
				for(TimeCondition time2:list_time ){
					pkt2=new PacketFilterCondition();
					pkt2.setSourceAddress(sourceAddress);
					fcc = new FilteringConfigurationCondition();

					fcc.setApplicationLayerCondition(app);
					fcc.setPacketFilterCondition(pkt2);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);

					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);


				}
				if(list_time.size()==0){
					pkt2=new PacketFilterCondition();
					pkt2.setSourceAddress(sourceAddress);
					fcc = new FilteringConfigurationCondition();

					fcc.setApplicationLayerCondition(app);
					fcc.setPacketFilterCondition(pkt2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);
				}


			}

			for(PacketFilterCondition pkt3: list_pfc ){
				for(TimeCondition time2:list_time ){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);


				}

				if(list_time.size()==0){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);

				}
			}

			if(list_pfc.size()==0 && list_app.size()==0){

				for(TimeCondition time2:list_time ){
					pkt2=new PacketFilterCondition();
					pkt2.setSourceAddress(sourceAddress);
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt2);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);


				}
			}


		}else{

			ConfigurationRule rule;
			PacketFilterCondition pkt2;
			FilteringConfigurationCondition fcc; 

			pkt2=new PacketFilterCondition();
			pkt2.setSourceAddress(sourceAddress);
			fcc = new FilteringConfigurationCondition();

			fcc.setPacketFilterCondition(pkt2);

			rule=new ConfigurationRule();
			HSPL h_string=new HSPL();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationCondition(fcc);

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				rule.setConfigurationRuleAction(allow);
			else
				rule.setConfigurationRuleAction(deny);

			rule.setIsCNF(false);
			Priority ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);



		}




	}


	public static void setMSPLConfiguration_Filtering_VoIP(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects,  AssociationList target, int i){

		HashMap<String, Association> target_map=new HashMap<String, Association>();



		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				conf.setDefaultAction(deny);
			else			
				conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();



		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";







		if(h.getFields().getTimePeriod()!=null || h.getFields().getSpecificURL()!=null || h.getFields().getTrafficTarget()!=null || h.getFields().getTypeContent()!=null ){

			//if(h.getFields()!=null){

			//time Conditions 
			TimeCondition time = null; 
			String hour_string;
			String week_string;

			if(h.getFields().getTimePeriod()!=null && p.getCapability().getCapabilityList().contains(Capability.TIMING)){

				for(TimeInterval t: h.getFields().getTimePeriod().getIntervalTime()){
					time= new TimeCondition();
					hour_string="";
					week_string="";

					for(TimeHour hour:t.getTimeHours()){
						//hour_string+=hour.getStartTime().toString()+"-"+hour.getEndTime().toString()+",";
						String start=hour.getStartTime().toString();
						String[] parts = start.split(":");
						start=parts[0]+":"+parts[1];
						String end= hour.getEndTime().toString();
						parts =end.split(":");
						end=parts[0]+":"+parts[1];
						hour_string+=start+"-"+end+",";
					}

					for(WeekDay w: t.getWeekDay()){
						week_string+=w.toString()+",";

					}
					time.setTime(h.getFields().getTimePeriod().getTimeZone());
					time.setTime(hour_string);
					time.setWeekday(week_string);
					list_time.add(time);
				}
			}




			PacketFilterCondition pkt_TCP, pkt_UDP, pkt_TCP_UDP;


			if(h.getFields().getTrafficTarget()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_4) ){
				String ip_dest="";
				pkt_TCP=new PacketFilterCondition();
				pkt_UDP=new PacketFilterCondition();
				pkt_TCP_UDP=new PacketFilterCondition();

				for(String s: h.getFields().getTrafficTarget().getTargetName() )
					if(target_map.containsKey(s))
						for(IP ip: target_map.get(s).getIP())
							ip_dest+=ip.getIpValue()+",";

				if(!ip_dest.equals("")){

					pkt_TCP.setDestinationAddress(ip_dest);
					pkt_TCP.setSourceAddress(sourceAddress);

					pkt_UDP.setDestinationAddress(ip_dest);
					pkt_UDP.setSourceAddress(sourceAddress);

					pkt_TCP_UDP.setDestinationAddress(ip_dest);
					pkt_TCP_UDP.setSourceAddress(sourceAddress);




					pkt_TCP_UDP.setDestinationPort("5060,5061");
					pkt_TCP.setDestinationPort("389,4000-4005,522,1731,1720");
					pkt_TCP.setProtocolType("TCP");
					pkt_UDP.setDestinationPort("16384-32767");
					pkt_UDP.setProtocolType("UDP");


					list_pfc.add(pkt_TCP_UDP);
					list_pfc.add(pkt_TCP);
					list_pfc.add(pkt_UDP);

				}					

			}




			ConfigurationRule rule;
			//PacketFilterCondition pkt2;
			FilteringConfigurationCondition fcc; 




			for(PacketFilterCondition pkt3: list_pfc ){
				for(TimeCondition time2:list_time ){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);


				}

				if(list_time.size()==0){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);

				}
			}

			if(list_pfc.size()==0){

				for(TimeCondition time2:list_time ){
					Priority ed1;

					pkt_TCP=new PacketFilterCondition();
					pkt_UDP=new PacketFilterCondition();
					pkt_TCP_UDP=new PacketFilterCondition();

					pkt_TCP.setSourceAddress(sourceAddress);
					pkt_UDP.setSourceAddress(sourceAddress);
					pkt_TCP_UDP.setSourceAddress(sourceAddress);

					pkt_TCP_UDP.setDestinationPort("5060,5061");
					pkt_TCP.setDestinationPort("389,4000-4005,522,1731,1720");
					pkt_TCP.setProtocolType("TCP");
					pkt_UDP.setDestinationPort("16384-32767");
					pkt_UDP.setProtocolType("UDP");


					//TCP
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt_TCP);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);



					//UDP
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt_UDP);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);


					//TCP+UDP
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt_TCP_UDP);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();

					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);




				}
			}


		}else{

			ConfigurationRule rule;
			FilteringConfigurationCondition fcc; 
			PacketFilterCondition pkt_TCP, pkt_UDP, pkt_TCP_UDP;

			Priority ed1;

			pkt_TCP=new PacketFilterCondition();
			pkt_UDP=new PacketFilterCondition();
			pkt_TCP_UDP=new PacketFilterCondition();

			pkt_TCP.setSourceAddress(sourceAddress);
			pkt_UDP.setSourceAddress(sourceAddress);
			pkt_TCP_UDP.setSourceAddress(sourceAddress);

			pkt_TCP_UDP.setDestinationPort("5060,5061");
			pkt_TCP.setDestinationPort("389,4000-4005,522,1731,1720");
			pkt_TCP.setProtocolType("TCP");
			pkt_UDP.setDestinationPort("16384-32767");
			pkt_UDP.setProtocolType("UDP");


			//TCP
			fcc = new FilteringConfigurationCondition();

			fcc.setPacketFilterCondition(pkt_TCP);

			rule=new ConfigurationRule();
			HSPL h_string=new HSPL();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationCondition(fcc);

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				rule.setConfigurationRuleAction(allow);
			else
				rule.setConfigurationRuleAction(deny);

			rule.setIsCNF(false);
			ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);



			//UDP
			fcc = new FilteringConfigurationCondition();

			fcc.setPacketFilterCondition(pkt_UDP);

			rule=new ConfigurationRule();

			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationCondition(fcc);

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				rule.setConfigurationRuleAction(allow);
			else
				rule.setConfigurationRuleAction(deny);

			rule.setIsCNF(false);
			ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);


			//TCP+UDP
			fcc = new FilteringConfigurationCondition();

			fcc.setPacketFilterCondition(pkt_TCP_UDP);

			rule=new ConfigurationRule();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);
			rule.setConfigurationCondition(fcc);

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				rule.setConfigurationRuleAction(allow);
			else
				rule.setConfigurationRuleAction(deny);

			rule.setIsCNF(false);
			ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);




		}




















	}


	public static void setMSPLConfiguration_Filtering_DNS(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects,  AssociationList target, int i){


		HashMap<String, Association> target_map=new HashMap<String, Association>();


		//for specific 
		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				conf.setDefaultAction(deny);
			else			
				conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
		HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();



		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";







		if(h.getFields().getTimePeriod()!=null || h.getFields().getSpecificURL()!=null || h.getFields().getTrafficTarget()!=null || h.getFields().getTypeContent()!=null ){

			//if(h.getFields()!=null){

			//time Conditions 
			TimeCondition time = null; 
			String hour_string;
			String week_string;

			if(h.getFields().getTimePeriod()!=null && p.getCapability().getCapabilityList().contains(Capability.TIMING)){

				for(TimeInterval t: h.getFields().getTimePeriod().getIntervalTime()){
					time= new TimeCondition();
					hour_string="";
					week_string="";

					for(TimeHour hour:t.getTimeHours()){
						//hour_string+=hour.getStartTime().toString()+"-"+hour.getEndTime().toString()+",";

						String start=hour.getStartTime().toString();
						String[] parts = start.split(":");
						start=parts[0]+":"+parts[1];
						String end= hour.getEndTime().toString();
						parts =end.split(":");
						end=parts[0]+":"+parts[1];
						hour_string+=start+"-"+end+",";
					}

					for(WeekDay w: t.getWeekDay()){
						week_string+=w.toString()+",";

					}
					time.setTime(h.getFields().getTimePeriod().getTimeZone());
					time.setTime(hour_string);
					time.setWeekday(week_string);
					list_time.add(time);
				}
			}

			PacketFilterCondition  pkt_UDP;


			/*     

			if(h.getFields().getTrafficTarget()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_4) ){

				pkt_UDP=new PacketFilterCondition();
				pkt_UDP.setSourceAddress(sourceAddress);
				pkt_UDP.setDestinationPort("53,5353");


				String ip_dest="";

				for(String s: h.getFields().getTrafficTarget().getTargetName() )
					if(target_map.containsKey(s))
						for(IP ip: target_map.get(s).getIP())
							ip_dest+=ip.getIpValue()+",";



				if(!ip_dest.equals("")){
					pkt_UDP.setDestinationAddress(ip_dest);
				}

					list_pfc.add(pkt_UDP);






			}*/

			/*ApplicationLayerCondition alc;

			//Traffic Ispection
			if(h.getFields().getTypeContent()!=null && p.getCapability().getCapabilityList().contains(Capability.TRAFFIC_INSPECTION_L_7)  ){
				String name="";
				alc= new ApplicationLayerCondition();						

				for (String s: h.getFields().getTypeContent().getContentName())
					name+=s+",";

				alc.setPhrase(name);

				list_app.add(alc);
			}
			 */



			ConfigurationRule rule;
			FilteringConfigurationCondition fcc; 




			for(PacketFilterCondition pkt3: list_pfc ){
				for(TimeCondition time2:list_time ){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);


				}

				if(list_time.size()==0){
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt3);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					Priority ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;

					conf.getConfigurationRule().add(rule);

				}
			}

			if(list_pfc.size()==0){

				for(TimeCondition time2:list_time ){
					Priority ed1;


					pkt_UDP=new PacketFilterCondition();
					pkt_UDP.setSourceAddress(sourceAddress);
					pkt_UDP.setDestinationPort("53,5353");



					//UDP
					fcc = new FilteringConfigurationCondition();

					fcc.setPacketFilterCondition(pkt_UDP);
					fcc.setTimeCondition(time2);

					rule=new ConfigurationRule();
					HSPL h_string=new HSPL();
					h_string.setHSPLId(h.getId());
					h_string.setHSPLText(getHSPL(h));
					rule.getHSPL().add(h_string);
					rule.setConfigurationCondition(fcc);

					if(h.getAction().equals(Action.AUTHORISE_ACCESS))
						rule.setConfigurationRuleAction(allow);
					else
						rule.setConfigurationRuleAction(deny);

					rule.setIsCNF(false);
					ed1 = new Priority();
					ed1.setValue(BigInteger.valueOf(i));
					rule.setExternalData(ed1);
					rule.setName("Rule"+i);
					i++;
					conf.getConfigurationRule().add(rule);







				}
			}


		}else{

			ConfigurationRule rule;
			FilteringConfigurationCondition fcc; 
			PacketFilterCondition  pkt_UDP ;

			Priority ed1;

			pkt_UDP=new PacketFilterCondition();

			pkt_UDP.setSourceAddress(sourceAddress);


			pkt_UDP.setDestinationPort("53,5353");





			//UDP
			fcc = new FilteringConfigurationCondition();

			fcc.setPacketFilterCondition(pkt_UDP);

			rule=new ConfigurationRule();
			HSPL h_string=new HSPL();
			h_string.setHSPLId(h.getId());
			h_string.setHSPLText(getHSPL(h));
			rule.getHSPL().add(h_string);

			rule.setConfigurationCondition(fcc);

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				rule.setConfigurationRuleAction(allow);
			else
				rule.setConfigurationRuleAction(deny);

			rule.setIsCNF(false);
			ed1 = new Priority();
			ed1.setValue(BigInteger.valueOf(i));
			rule.setExternalData(ed1);
			rule.setName("Rule"+i);
			i++;
			conf.getConfigurationRule().add(rule);






		}













	}


	public static void setMSPLConfiguration_Filtering_P2P(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects, AssociationList content, AssociationList target, int i){

		HashMap<String, Association> contet_map=new HashMap<String, Association>();
		HashMap<String, Association> target_map=new HashMap<String, Association>();



		for(Association l: content.getAssociations()){
			contet_map.put(l.getName(),l);
		}

		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				conf.setDefaultAction(deny);
			else			
				conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
		HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();




		//ConfigurationRule rule1 = new ConfigurationRule();





		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";



		//destAddress
		if(target_map.containsKey("P2P")){
			String destAddress="";


			Association ass_intranet=target_map.get("P2P");

			for(IP ip: ass_intranet.getIP())
				destAddress+=ip.getIpValue()+",";


			if(h.getFields().getTimePeriod()!=null || h.getFields().getSpecificURL()!=null || h.getFields().getTrafficTarget()!=null || h.getFields().getTypeContent()!=null ){

				//if(h.getFields()!=null){

				//time Conditions 
				TimeCondition time = null; 
				String hour_string;
				String week_string;

				if(h.getFields().getTimePeriod()!=null && p.getCapability().getCapabilityList().contains(Capability.TIMING)){

					for(TimeInterval t: h.getFields().getTimePeriod().getIntervalTime()){
						time= new TimeCondition();
						hour_string="";
						week_string="";

						for(TimeHour hour:t.getTimeHours()){
							//hour_string+=hour.getStartTime().toString()+"-"+hour.getEndTime().toString()+",";

							String start=hour.getStartTime().toString();
							String[] parts = start.split(":");
							start=parts[0]+":"+parts[1];
							String end= hour.getEndTime().toString();
							parts =end.split(":");
							end=parts[0]+":"+parts[1];
							hour_string+=start+"-"+end+",";

						}

						for(WeekDay w: t.getWeekDay()){
							week_string+=w.toString()+",";

						}
						time.setTime(h.getFields().getTimePeriod().getTimeZone());
						time.setTime(hour_string);
						time.setWeekday(week_string);
						list_time.add(time);
					}
				}



				ApplicationLayerCondition alc;
				if(h.getFields().getTypeContent()!=null && p.getCapability().getCapabilityList().contains(Capability.TRAFFIC_INSPECTION_L_7)  ){
					String name="";
					alc= new ApplicationLayerCondition();						

					for (String s: h.getFields().getTypeContent().getContentName())
						name+=s+",";

					alc.setURLRegex(name);

					list_app.add(alc);
				}





				ConfigurationRule rule;
				PacketFilterCondition pkt2;
				FilteringConfigurationCondition fcc; 

				for(ApplicationLayerCondition app:list_app ){
					for(TimeCondition time2:list_time ){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);
						fcc = new FilteringConfigurationCondition();

						fcc.setApplicationLayerCondition(app);
						fcc.setPacketFilterCondition(pkt2);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);


					}
					if(list_time.size()==0){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);

						fcc = new FilteringConfigurationCondition();

						fcc.setApplicationLayerCondition(app);
						fcc.setPacketFilterCondition(pkt2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);
					}


				}

				for(PacketFilterCondition pkt3: list_pfc ){
					for(TimeCondition time2:list_time ){
						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt3);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;

						conf.getConfigurationRule().add(rule);


					}

					if(list_time.size()==0){
						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt3);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;

						conf.getConfigurationRule().add(rule);

					}
				}

				if(list_pfc.size()==0 && list_app.size()==0){

					for(TimeCondition time2:list_time ){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);

						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt2);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);


					}
				}


			}else{

				ConfigurationRule rule;
				PacketFilterCondition pkt2;
				FilteringConfigurationCondition fcc; 

				pkt2=new PacketFilterCondition();
				pkt2.setSourceAddress(sourceAddress);
				pkt2.setDestinationAddress(destAddress);

				fcc = new FilteringConfigurationCondition();

				fcc.setPacketFilterCondition(pkt2);

				rule=new ConfigurationRule();
				HSPL h_string=new HSPL();
				h_string.setHSPLId(h.getId());
				h_string.setHSPLText(getHSPL(h));
				rule.getHSPL().add(h_string);

				rule.setConfigurationCondition(fcc);

				if(h.getAction().equals(Action.AUTHORISE_ACCESS))
					rule.setConfigurationRuleAction(allow);
				else
					rule.setConfigurationRuleAction(deny);

				rule.setIsCNF(false);
				Priority ed1 = new Priority();
				ed1.setValue(BigInteger.valueOf(i));
				rule.setExternalData(ed1);
				rule.setName("Rule"+i);
				i++;
				conf.getConfigurationRule().add(rule);



			}



		}

	}


	public static void setMSPLConfiguration_Filtering_Intranet(Hspl h, PSA p,RuleSetConfiguration conf,AssociationList subjects, AssociationList content, AssociationList target, int i){

		HashMap<String, Association> contet_map=new HashMap<String, Association>();
		HashMap<String, Association> target_map=new HashMap<String, Association>();



		for(Association l: content.getAssociations()){
			contet_map.put(l.getName(),l);
		}

		for(Association l: target.getAssociations()){
			target_map.put(l.getName(),l);
		}




		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");


		// DefaultAction
		if(conf.getDefaultAction()==null){

			if(h.getAction().equals(Action.AUTHORISE_ACCESS))
				conf.setDefaultAction(deny);
			else			
				conf.setDefaultAction(allow);
		}


		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);



		HashSet<PacketFilterCondition> list_pfc=new HashSet<PacketFilterCondition>();
		HashSet<TimeCondition> list_time= new HashSet<TimeCondition>();
		HashSet<ApplicationLayerCondition> list_app= new HashSet<ApplicationLayerCondition>();




		//ConfigurationRule rule1 = new ConfigurationRule();





		//sourceAddress
		String sourceAddress="";
		for (Association a: subjects.getAssociations())
			if(h.getSubject().compareTo(a.getName())==0)			
				for(IP ip: a.getIP())
					sourceAddress+=ip.getIpValue()+",";



		//destAddress
		if(target_map.containsKey("Intranet")){
			String destAddress="";


			Association ass_intranet=target_map.get("Intranet");

			for(IP ip: ass_intranet.getIP())
				destAddress+=ip.getIpValue()+",";


			if(h.getFields().getTimePeriod()!=null || h.getFields().getSpecificURL()!=null || h.getFields().getTrafficTarget()!=null || h.getFields().getTypeContent()!=null ){

				//if(h.getFields()!=null){

				//time Conditions 
				TimeCondition time = null; 
				String hour_string;
				String week_string;

				if(h.getFields().getTimePeriod()!=null && p.getCapability().getCapabilityList().contains(Capability.TIMING)){

					for(TimeInterval t: h.getFields().getTimePeriod().getIntervalTime()){
						time= new TimeCondition();
						hour_string="";
						week_string="";

						for(TimeHour hour:t.getTimeHours()){
							//hour_string+=hour.getStartTime().toString()+"-"+hour.getEndTime().toString()+",";

							String start=hour.getStartTime().toString();
							String[] parts = start.split(":");
							start=parts[0]+":"+parts[1];
							String end= hour.getEndTime().toString();
							parts =end.split(":");
							end=parts[0]+":"+parts[1];
							hour_string+=start+"-"+end+",";
						}

						for(WeekDay w: t.getWeekDay()){
							week_string+=w.toString()+",";

						}
						time.setTime(h.getFields().getTimePeriod().getTimeZone());
						time.setTime(hour_string);
						time.setWeekday(week_string);
						list_time.add(time);
					}
				}

				//	ApplicationLayerCondition 

				ApplicationLayerCondition alc;
				if(h.getFields().getSpecificURL()!=null && p.getCapability().getCapabilityList().contains(Capability.FILTERING_L_7)){
					String urls="";
					alc= new ApplicationLayerCondition();						
					for (String s: h.getFields().getSpecificURL().getURL()){


						if(contet_map.containsKey(s))
							//list of URL
							for(URI s1: contet_map.get(s).getURI())
								urls+=s1.getURIValue()+",";
						else //singol URL
							urls+=s+",";

					}
					alc.setURL(urls);

					list_app.add(alc);
				}


				if(h.getFields().getTypeContent()!=null && p.getCapability().getCapabilityList().contains(Capability.TRAFFIC_INSPECTION_L_7)  ){
					String name="";
					alc= new ApplicationLayerCondition();						

					for (String s: h.getFields().getTypeContent().getContentName())
						name+=s+",";

					alc.setURLRegex(name);

					list_app.add(alc);
				}





				ConfigurationRule rule;
				PacketFilterCondition pkt2;
				FilteringConfigurationCondition fcc; 

				for(ApplicationLayerCondition app:list_app ){
					for(TimeCondition time2:list_time ){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);
						fcc = new FilteringConfigurationCondition();

						fcc.setApplicationLayerCondition(app);
						fcc.setPacketFilterCondition(pkt2);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);


					}
					if(list_time.size()==0){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);

						fcc = new FilteringConfigurationCondition();

						fcc.setApplicationLayerCondition(app);
						fcc.setPacketFilterCondition(pkt2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);
					}


				}

				for(PacketFilterCondition pkt3: list_pfc ){
					for(TimeCondition time2:list_time ){
						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt3);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;

						conf.getConfigurationRule().add(rule);


					}

					if(list_time.size()==0){
						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt3);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;

						conf.getConfigurationRule().add(rule);

					}
				}

				if(list_pfc.size()==0 && list_app.size()==0){

					for(TimeCondition time2:list_time ){
						pkt2=new PacketFilterCondition();
						pkt2.setSourceAddress(sourceAddress);
						pkt2.setDestinationAddress(destAddress);

						fcc = new FilteringConfigurationCondition();

						fcc.setPacketFilterCondition(pkt2);
						fcc.setTimeCondition(time2);

						rule=new ConfigurationRule();
						HSPL h_string=new HSPL();
						h_string.setHSPLId(h.getId());
						h_string.setHSPLText(getHSPL(h));
						rule.getHSPL().add(h_string);

						rule.setConfigurationCondition(fcc);

						if(h.getAction().equals(Action.AUTHORISE_ACCESS))
							rule.setConfigurationRuleAction(allow);
						else
							rule.setConfigurationRuleAction(deny);

						rule.setIsCNF(false);
						Priority ed1 = new Priority();
						ed1.setValue(BigInteger.valueOf(i));
						rule.setExternalData(ed1);
						rule.setName("Rule"+i);
						i++;
						conf.getConfigurationRule().add(rule);


					}
				}


			}else{

				ConfigurationRule rule;
				PacketFilterCondition pkt2;
				FilteringConfigurationCondition fcc; 

				pkt2=new PacketFilterCondition();
				pkt2.setSourceAddress(sourceAddress);
				pkt2.setDestinationAddress(destAddress);

				fcc = new FilteringConfigurationCondition();

				fcc.setPacketFilterCondition(pkt2);

				rule=new ConfigurationRule();
				HSPL h_string=new HSPL();
				h_string.setHSPLId(h.getId());
				h_string.setHSPLText(getHSPL(h));
				rule.getHSPL().add(h_string);

				rule.setConfigurationCondition(fcc);

				if(h.getAction().equals(Action.AUTHORISE_ACCESS))
					rule.setConfigurationRuleAction(allow);
				else
					rule.setConfigurationRuleAction(deny);

				rule.setIsCNF(false);
				Priority ed1 = new Priority();
				ed1.setValue(BigInteger.valueOf(i));
				rule.setExternalData(ed1);
				rule.setName("Rule"+i);
				i++;
				conf.getConfigurationRule().add(rule);



			}



		}

	}

	public static void setMSPLConfiguration_Enable(Hspl h, PSA p, RuleSetConfiguration conf) {


		EnableAction a=new EnableAction();
		EnableActionType at=new EnableActionType();
		at.setEnable(true);
		at.setObjectToEnable(p.getName());
		a.setEnableActionType(at);
		conf.setDefaultAction(a);
		ConfigurationRule rule=new ConfigurationRule();
		HSPL h_string=new HSPL();
		h_string.setHSPLId(h.getId());
		h_string.setHSPLText(getHSPL(h));
		rule.getHSPL().add(h_string);

		conf.getConfigurationRule().add(rule);
		//Resolution Strategy
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);




	}















	public static void  run(Mapping map, Configurations conf, Schemas schemas){

		System.out.println("MSPL generator:");
		Matching matc=new Matching();
		String path=conf.getMsplDirOutput()+"match.xml";

		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.POLICY_MSPL)  ){
			getMSPL(map, matc, conf);
			Useful.mashal(matc, path,Matching.class );
			System.out.println("-Mapping");
		}

		else{


			HashSet<ITResource> itResource_list=new HashSet<ITResource>();


			AssociationList subjects= (AssociationList) Useful.unmashal(schemas.getAssociationListSchema(), conf.getSubjectFile(), AssociationList.class);
			AssociationList content= (AssociationList) Useful.unmashal(schemas.getAssociationListSchema(), conf.getContentFile(), AssociationList.class);
			AssociationList target= (AssociationList) Useful.unmashal(schemas.getAssociationListSchema(),conf.getTargetFile(), AssociationList.class);
			getMSPL(map,itResource_list,matc,subjects,content, target);


			System.out.print("-MSPL:");

			for (ITResource i: itResource_list){
				RuleSetConfiguration c=(RuleSetConfiguration) i.getConfiguration();
				path=conf.getMsplDirOutput()+c.getName()+".xml";
				Useful.mashal(i, path, ITResource.class );
				System.out.print(c.getName()+", ");

			}
			System.out.println();
			Useful.mashal(matc, path,Matching.class );
			System.out.println("-Mapping");

		}


	}


	public static void run (Configuration conf){


		System.out.println("MSPL generator:");
		Matching matc=new Matching();
		//String path=conf.getMsplDirOutput()+"match.xml";

		if(conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL) ||conf.getRefinementType().equals(RefinementType.APPLICATION_MSPL_SG) ||conf.getRefinementType().equals(RefinementType.POLICY_MSPL)  ){
			getMSPL(conf.getMap(), matc);
			//Useful.mashal(matc, path,Matching.class );

			conf.setMatching(matc);
			//System.out.println("-Mapping");
		}

		else{


			HashSet<ITResource> itResource_list=new HashSet<ITResource>();

			//getMSPL(conf.getMap(),itResource_list,matc,conf.getSubject(),conf.getContent(), conf.getTarget());


			System.out.print("-MSPL:");

			getMSPL(conf.getMap(),itResource_list,matc,conf.getSubject(),conf.getContent(), conf.getTarget());

			conf.setMspl_list(itResource_list);
			for (ITResource i: itResource_list){
				RuleSetConfiguration c=(RuleSetConfiguration) i.getConfiguration();
				System.out.print(c.getName()+", ");

			}
			System.out.println();
			conf.setMatching(matc);
			//System.out.println("-Mapping");
			Mapping sg_map=new Mapping();
			sg_map.setServiceGraph(conf.getMap().getServiceGraph());
			//Useful.mashal(sg_map, "./src/main/auxiliary_files/output/SG/Alice_SG_test.xml", Mapping.class);

		}





	}
}

