package eu.fp7.secured.mspl.test;

import java.io.File;
import java.math.BigInteger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import eu.fp7.secured.mspl.ApplicationLayerCondition;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.mspl.Configuration;
import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.ExternalData;
import eu.fp7.secured.mspl.FMR;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringCapability;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.PacketFilterCondition;
import eu.fp7.secured.mspl.Priority;
import eu.fp7.secured.mspl.RuleSetConfiguration;
import eu.fp7.secured.mspl.StatefulCondition;
import eu.fp7.secured.mspl.TimeCondition;

public class write_filter_xml {

	public static void main(String[] args) throws JAXBException {
		// TODO Auto-generated method stub
		ITResource itResource = new ITResource();

		
		
		RuleSetConfiguration conf = new RuleSetConfiguration();
		itResource.setConfiguration(conf);
		
		
		conf.setName("TestConf");
		
		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");
		
		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");
		
		conf.setDefaultAction(deny);
		
		FilteringCapability capability = new FilteringCapability();
		capability.setName("iptables");
		capability.setApplicationLayerFiltering(false);
		capability.setContentInspection(false);
		capability.setHttpFiltering(false);
		capability.setStateful(true);
		conf.setCapability(capability);
		
		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		
		ConfigurationRule rule1 = new ConfigurationRule();
		FilteringConfigurationCondition fcc = new FilteringConfigurationCondition();
		
		TimeCondition time = new TimeCondition();
		time.setTimeZone("UTC");
		time.setTime("8:00-12:00");
		time.setWeekday("M");
		fcc.setTimeCondition(time);
		
		ApplicationLayerCondition alc = new ApplicationLayerCondition();
		alc.setHttpMethod("GET");
		alc.setURL("google.com");
		fcc.setApplicationLayerCondition(alc);
		
		StatefulCondition sfc = new StatefulCondition();
		sfc.setLimitRuleHits("10");
		sfc.setState("ACK");
		fcc.setStatefulCondition(sfc);
		fcc.setIsCNF(false);
		
		PacketFilterCondition pfc = new PacketFilterCondition();
		pfc.setDestinationAddress("1.1.1.1");
		pfc.setDestinationPort("80");
		pfc.setDirection("IN");
		pfc.setInterface("eth0");
		pfc.setProtocolType("TCP");
		pfc.setSourceAddress("2.2.2.2");
		pfc.setSourcePort("80");
		fcc.setPacketFilterCondition(pfc);
		rule1.setConfigurationCondition(fcc);
		rule1.setConfigurationRuleAction(allow);
		Priority ed1 = new Priority();
		ed1.setValue(new BigInteger("1"));
		rule1.setExternalData(ed1);
		rule1.setIsCNF(false);
		rule1.setName("Rule1");
		conf.getConfigurationRule().add(rule1);
		
		// create JAXB context and instantiate marshaller
	    JAXBContext context = JAXBContext.newInstance(ITResource.class);
	    Marshaller m = context.createMarshaller();
	    m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

	    File file = new File("filter.xml");
	    
	    // Write to System.out
	    m.marshal(itResource, file);
	}

}
