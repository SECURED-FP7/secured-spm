/*
 * Export as runnable JAR
 */

package eu.securedfp7.m2lservice.plugin;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.RuleSetConfiguration;
import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.rule.impl.GenericRule;

import java.awt.geom.GeneralPath;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;

public class M2LPlugin {
	private static String securityControl = "iptables"; // type of security control,
													// e.g., netfilter, squid
	private static String version = "1.0"; // version
	private static String devlopedBy = "Politecnico di Torino"; // who developed
																// the plugin
	private static String providedBy = "SECURED project"; // who provided the
															// plugin

	public M2LPlugin(){
		
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
		boolean base64encode = false;
		int result = 0;
		
		// check if the input file is encoded as Base64	
		try {
			String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
			if(Base64.isBase64(inputString.getBytes())){
				base64encode = true;
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// if the input file is encoded in base64 we need to convert the file
		if(base64encode){
			try {
				String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
				MSPLFileName = MSPLFileName+".tmp";
				FileOutputStream out = new FileOutputStream(MSPLFileName);
				byte[] decodedBytes = Base64.decodeBase64(inputString.getBytes());
				out.write(decodedBytes);
				out.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		// replace quotations and \n from the input files
		try {
			String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
			inputString = inputString.replace("\\\"", "\"");
			inputString = inputString.replace("\\n", "");
			FileOutputStream out = new FileOutputStream(MSPLFileName);
			out.write(inputString.getBytes());
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			File file = new File(MSPLFileName);			
			Policy policy = PolicyWrapper.getFilteringPolicy(file,"");			
			String confFileString = getConf(policy);		
			
			
			File confFile = new File(securityControlFileName);
			
			try {
				BufferedWriter writer = new BufferedWriter(new FileWriter(confFile));
				writer.write(confFileString);
				writer.close();
			} catch (IOException e) {
				result = -1;
				e.printStackTrace();
				
			}
			
			
	 
		  } catch (Exception e) {
			result = -2;
			e.printStackTrace();
		}
		
		// if the input file is encoded in base64 we need to convert the output file to base64
		if(base64encode){
			try {
				String inputString = new String(Files.readAllBytes(Paths.get(securityControlFileName)));
				FileOutputStream out = new FileOutputStream(securityControlFileName);
				byte[] encodedBytes = Base64.encodeBase64(inputString.getBytes());
				out.write(encodedBytes);
				out.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return result;
	}
	
	private String getRule(GenericRule rule, String protocol){
		String result = "";
		
		String confRule = "-A FORWARD";
		
		confRule += " -p " + protocol;


		if (rule.getConditionClause().get("Interface") != null)
			confRule += " -i " + rule.getConditionClause().get("Interface").toSimpleString();
		
		if (rule.getConditionClause().get("Destination Address") != null){
			String ip_address = rule.getConditionClause().get("Destination Address").toSimpleString();
			if(!ip_address.equals("") && !ip_address.equals("empty")){
				String ip_ranges = "";
				String ip_list = "";
				for(String ip : ip_address.split(",")){
					if(ip.contains("-")){
						if(!ip_ranges.equals(""))
							ip_ranges += " -m iprange --dst-range ";
						ip_ranges += ip;
					} else {
						if(!ip_list.equals(""))
							ip_list += ",";
						ip_list += ip;
					}
				}
				if(!ip_ranges.equals(""))
					confRule += " -m iprange --dst-range  " + ip_ranges;
				if(!ip_list.equals(""))
					confRule += " -d  " + ip_list;
			}
		}
		if (rule.getConditionClause().get("Source Address") != null){
			String ip_address = rule.getConditionClause().get("Source Address").toSimpleString();
			if(!ip_address.equals("") && !ip_address.equals("empty")){
				String ip_ranges = "";
				String ip_list = "";
				for(String ip : ip_address.split(",")){
					if(ip.contains("-")){
						if(!ip_ranges.equals(""))
							ip_ranges += " -m iprange --src-range ";
						ip_ranges += ip;
					} else {
						if(!ip_list.equals(""))
							ip_list += ",";
						ip_list += ip;
					}
				}
				if(!ip_ranges.equals(""))
					confRule += " -m iprange --src-range  " + ip_ranges;
				if(!ip_list.equals(""))
					confRule += " -s  " + ip_list;
			}
		}
		/*
		if (rule.getConditionClause().get("Destination Port") != null)
			confRule += " -m multiport --dports " + rule.getConditionClause().get("Destination Port").toSimpleString().replace("-", ":");
		if (rule.getConditionClause().get("Source Port") != null)
			confRule += " -m multiport --sports " + rule.getConditionClause().get("Source Port").toSimpleString().replace("-", ":");
		*/
		
		if (rule.getConditionClause().get("Destination Port") != null){
						String port = rule.getConditionClause().get("Destination Port").toSimpleString();
						if(!port.equals("") && !port.equals("empty"))
							confRule += " -m multiport --dports " + port.replace("-", ":");
					}
					if (rule.getConditionClause().get("Source Port") != null){
						String port = rule.getConditionClause().get("Source Port").toSimpleString();
						if(!port.equals("") && !port.equals("empty"))
							confRule += " -m multiport --sports " + port.replace("-", ":");
					}
		
		if (rule.getConditionClause().get("RateLimit") != null)
			confRule += " -m limit --limit "+rule.getConditionClause().get("RateLimit").toSimpleString()+" --limit-burst 1";
		if (rule.getConditionClause().get("StateFul") != null)
			confRule += " -m conntrack --ctstate RELATED,ESTABLISHED";
		
		if (rule.getConditionClause().get("Time") != null || rule.getConditionClause().get("Weekday") != null){
			String week = "";
			String time = "";
			
			if (rule.getConditionClause().get("Weekday") != null)
				week = rule.getConditionClause().get("Weekday").toSimpleString();
			if (rule.getConditionClause().get("Time") != null)
				time = rule.getConditionClause().get("Time").toSimpleString();
			
			//if(!time.equals("*") && !time.equals("")){
			if(!time.equals("*") && !time.equals("")  && !time.equals("empty")){
				confRule += " -m time";
				if(time.contains(",")){
					String s[] = time.split(",");
					int i=0;
					
					for(; i<s.length-1; i++){
						String confRule1 = confRule.toString();
						confRule1 += " --timestart "+s[i].split("-")[0]+" --timestop "+s[i].split("-")[1];
						if(!week.equals("*") && !week.equals("")){
							confRule1 += " --weekdays "+ week;
						}
						String action = rule.getAction().toString();
						if(action.toUpperCase().equals("DENY"))
							confRule1 += " -j DROP\n";
						if(action.toUpperCase().equals("ALLOW"))
							confRule1 += " -j ACCEPT\n";
						result += confRule1;
						
					}
					confRule += " --timestart "+s[i].split("-")[0]+" --timestop "+s[i].split("-")[1];
				} else {
					confRule += " --timestart "+time.split("-")[0]+" --timestop "+time.split("-")[1];
				}
				//if(!week.equals("*") && !week.equals("")){
				if(!week.equals("*") && !week.equals("") && !week.equals("empty")){
					confRule += " --weekdays "+ week;
				} 
			} else {
				//if(week.equals("*") && !week.equals("")){
				if(!week.equals("*") && !week.equals("") && !week.equals("empty")){
					confRule += "-m time --weekdays "+ week;
				} 
			}
		}

		String action = rule.getAction().toString();
		if (action.toUpperCase().equals("DENY"))
			confRule += " -j DROP\n";
		if (action.toUpperCase().equals("ALLOW"))
			confRule += " -j ACCEPT\n";
		
		return result+confRule;
	}

	public String getConf(Policy policy) throws JAXBException {

		String confFile = "*filter\n";

		confFile += ":INPUT ACCEPT [0:0]\n";
		confFile += ":OUTPUT ACCEPT [0:0]\n";

		String action = policy.getDefaultAction().toString();

		if (action.toUpperCase().equals("DENY"))
			confFile += ":FORWARD DROP [0:0]\n";
		if (action.toUpperCase().equals("ALLOW"))
			confFile += ":FORWARD ACCEPT [0:0]\n";

		LinkedList<GenericRule> rules = new LinkedList<GenericRule>();
		rules.addAll(policy.getRuleSet());
		Collections.sort(rules, new RuleComparator(policy));

		for (GenericRule rule : rules) {
			String protocols = "*";
			if(rule.getConditionClause().get("Protocol") != null){
				protocols = rule.getConditionClause().get("Protocol").toSimpleString().trim();
			}
			for(String protocol:protocols.split(","))
			{
				if(protocol.equals("*") && !protocol.equals("")){
					confFile += getRule(rule, "TCP");
					confFile += getRule(rule, "UDP");
				} else {
					confFile += getRule(rule, protocol);
				}
			}
			
		}

		confFile += "COMMIT\n";
		return confFile;
	}


}