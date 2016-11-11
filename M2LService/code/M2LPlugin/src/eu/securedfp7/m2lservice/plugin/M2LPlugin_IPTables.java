package eu.securedfp7.m2lservice.plugin;

import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.RuleSetConfiguration;

import java.awt.geom.GeneralPath;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class M2LPlugin_IPTables {
	private static String securityControl = "iptables"; // type of security control,
													// e.g., netfilter, squid
	private static String version = "1.0"; // version
	private static String devlopedBy = "Politecnico di Torino"; // who developed
																// the plugin
	private static String providedBy = "SECURED project"; // who provided the
															// plugin

	public M2LPlugin_IPTables(){
		
	}
	
	public String getType() {
		return this.securityControl;
	}

	public String getVersion() {
		return this.version;
	}

	public String developedBy() {
		return this.devlopedBy;
	}

	public String providedBy() {
		return this.providedBy;
	}

	/**
	 * Perform the translation
	 * 
	 * @param MSPLFileName
	 *            : MSPL file name
	 * @param securityControlFileName
	 *            : output file
	 * @return
	 */
	public int getConfiguration(String MSPLFileName, String securityControlFileName) {
		int result = 0;

		try {
			
	 
			File file = new File(MSPLFileName);
			JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
	 
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(file);
			
			String confFile = "";
			
			confFile += ":INPUT DROP [0:0]\n";
			confFile += ":FORWARD DROP [0:0]\n";
			
			String action = ((FilteringAction)((RuleSetConfiguration) itResource.getConfiguration()).getDefaultAction()).getFilteringActionType();
			
			if(action.toUpperCase().equals("DENY"))
				confFile += ":OUTPUT DROP [0:0]\n";
			if(action.toUpperCase().equals("ALLOW"))
				confFile += ":OUTPUT ACCEPT [0:0]\n";
			
			RuleSetConfiguration ruleset = (RuleSetConfiguration) itResource.getConfiguration();
			
			for(ConfigurationRule rule:ruleset.getConfigurationRule()){
				String confRule = "-A FORWARD";
				
				FilteringConfigurationCondition fcc = (FilteringConfigurationCondition)rule.getConfigurationCondition();
				
				if(fcc.getPacketFilterCondition()!=null){
					if(fcc.getPacketFilterCondition().getInterface()!=null && !fcc.getPacketFilterCondition().getInterface().equals("*") && !fcc.getPacketFilterCondition().getInterface().equals("")){
						confRule += " -i " + fcc.getPacketFilterCondition().getInterface().toLowerCase();
					}
					
					if(fcc.getPacketFilterCondition().getProtocolType()!=null && !fcc.getPacketFilterCondition().getProtocolType().equals("*")&& !fcc.getPacketFilterCondition().getProtocolType().equals("")){
						confRule += " -p " + fcc.getPacketFilterCondition().getProtocolType().toLowerCase();
					} else {
						confRule += " -p tcp|udp";
					}
					
					if(fcc.getPacketFilterCondition().getDestinationPort() != null && !fcc.getPacketFilterCondition().getDestinationPort().equals("*") && !fcc.getPacketFilterCondition().getDestinationPort().equals("")){
						confRule += " --dport " + fcc.getPacketFilterCondition().getDestinationPort();
					}
					
					if(fcc.getPacketFilterCondition().getSourcePort() != null && !fcc.getPacketFilterCondition().getSourcePort().equals("*") && !fcc.getPacketFilterCondition().getSourcePort().equals("")){
						confRule += " --sport " + fcc.getPacketFilterCondition().getSourcePort();
					}
					
					if(fcc.getPacketFilterCondition().getSourceAddress()!=null && !fcc.getPacketFilterCondition().getSourceAddress().equals("*") && !fcc.getPacketFilterCondition().getSourceAddress().equals("")){
						confRule += " -s " + fcc.getPacketFilterCondition().getSourceAddress();
					}
					
					if(fcc.getPacketFilterCondition().getDestinationAddress()!=null && !fcc.getPacketFilterCondition().getDestinationAddress().equals("*") && !fcc.getPacketFilterCondition().getDestinationAddress().equals("")){
						confRule += " -d " + fcc.getPacketFilterCondition().getDestinationAddress();
					}
					
					
				}
				
				if(fcc.getStatefulCondition()!=null){
					if(fcc.getStatefulCondition().getState()!=null && !fcc.getStatefulCondition().getState().equals("*") && !fcc.getStatefulCondition().getState().equals("")){
						if(fcc.getStatefulCondition().getState().toLowerCase().equals("establishedrelated"))
							confRule += " -m conntrack --ctstate RELATED,ESTABLISHED";
					}
					if(fcc.getStatefulCondition().getLimitRuleHits()!=null && !fcc.getStatefulCondition().getLimitRuleHits().equals("*") && !fcc.getStatefulCondition().getLimitRuleHits().equals(""))
						confRule += " -m limit --limit "+fcc.getStatefulCondition().getLimitRuleHits()+" --limit-burst 1";
				}
				
				if(fcc.getTimeCondition()!=null){
					confRule += " -m time";
					if(fcc.getTimeCondition().getTime()!=null && !fcc.getTimeCondition().getTime().equals("*") && !fcc.getTimeCondition().getTime().equals("")){
						if(fcc.getTimeCondition().getTime().contains(",")){
							String s[] = fcc.getTimeCondition().getTime().split(",");
							int i=0;
							
							for(; i<s.length-1; i++){
								String confRule1 = confRule.toString();
								confRule1 += " --timestart "+s[i].split("-")[0]+" --timestop "+s[i].split("-")[1];
								if(fcc.getTimeCondition().getWeekday()!=null && !fcc.getTimeCondition().getWeekday().equals("*") && !fcc.getTimeCondition().getWeekday().equals("")){
									confRule1 += " --weekdays "+ fcc.getTimeCondition().getWeekday();
								} 
								if(fcc.getTimeCondition().getTimeZone()!=null && !fcc.getTimeCondition().getTimeZone().equals("UTC"))
										confRule += " -kerneltz";
								action = ((FilteringAction)rule.getConfigurationRuleAction()).getFilteringActionType();
								if(action.toUpperCase().equals("DENY"))
									confRule1 += " -j DROP\n";
								if(action.toUpperCase().equals("ALLOW"))
									confRule1 += " -j ACCEPT\n";
								confFile += confRule1;
								
							}
							confRule += " --timestart "+s[i].split("-")[0]+" --timestop "+s[i].split("-")[1];
						} else {
							confRule += " --timestart "+fcc.getTimeCondition().getTime().split("-")[0]+" --timestop "+fcc.getTimeCondition().getTime().split("-")[1];
						}
					} else {
						confRule += " --timestart 00:00 --timestop 23:59";
					}
					
					if(fcc.getTimeCondition().getWeekday()!=null && !fcc.getTimeCondition().getWeekday().equals("*") && !fcc.getTimeCondition().getWeekday().equals("")){
						confRule += " --weekdays "+ fcc.getTimeCondition().getWeekday();
					} 
					
					confRule += " -kerneltz";
				}
				
				action = ((FilteringAction)rule.getConfigurationRuleAction()).getFilteringActionType();
				if(action.toUpperCase().equals("DENY"))
					confRule += " -j DROP\n";
				if(action.toUpperCase().equals("ALLOW"))
					confRule += " -j ACCEPT\n";
				
				confFile += confRule;
			}
			
			confFile += "COMMIT\n";
			
			
			File logFile = new File(securityControlFileName);

			
			try {
				BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
				writer.write(confFile);
				writer.close();
			} catch (IOException e) {
				result = -1;
				e.printStackTrace();
				
			}
			
			
	 
		  } catch (JAXBException e) {
			result = -2;
			e.printStackTrace();
		  }

		return result;
	}

	/*
	 * public static void main(String[] args) { // TODO Auto-generated method
	 * stub
	 * 
	 * }
	 */

}
