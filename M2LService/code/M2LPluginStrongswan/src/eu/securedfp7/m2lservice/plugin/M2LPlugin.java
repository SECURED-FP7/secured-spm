package eu.securedfp7.m2lservice.plugin;

import java.io.BufferedWriter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;

//import com.sun.corba.se.spi.orbutil.fsm.Action;

import main.java.mspl_class.ActionParameters;
import main.java.mspl_class.AdditionalNetworkConfigurationParameters;
import main.java.mspl_class.Authentication;
import main.java.mspl_class.AuthenticationParameters;
import main.java.mspl_class.Confidentiality;
import main.java.mspl_class.ConfigurationRule;
import main.java.mspl_class.DataProtectionAction;
import main.java.mspl_class.IKETechnologyParameter;
import main.java.mspl_class.IPsecTechnologyParameter;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.Integrity;
import main.java.mspl_class.RemoteAccessNetworkConfiguration;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.TechnologyActionSecurityProperty;
import main.java.mspl_class.TechnologySpecificParameters;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;


public class M2LPlugin {
	private static String securityControl = "strongswan"; // type of security control,
													// e.g., netfilter, squid
	private static String version = "1.0"; // version
	private static String devlopedBy = "UPC"; // who developed
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
		String content = "";
		
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

			File mspl = new File(MSPLFileName);
			File confFile = new File(securityControlFileName);

			try {
				JAXBContext jaxbContext = JAXBContext
						.newInstance(ITResource.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext
						.createUnmarshaller();
				ITResource itResource = (ITResource) jaxbUnmarshaller
						.unmarshal(mspl);
				
				RuleSetConfiguration rule_set = (RuleSetConfiguration) itResource
						.getConfiguration();
				JSONObject defaultConfigObj = new JSONObject();
				JSONObject psaConfigObj = new JSONObject();
				

				for (ConfigurationRule rule : rule_set.getConfigurationRule()) {
					DataProtectionAction dpa = (DataProtectionAction) rule.getConfigurationRuleAction();
					ActionParameters action_params = dpa.getTechnologyActionParameters();
					for(TechnologySpecificParameters tsp : action_params.getTechnologyParameter()){
						
						if(tsp.getClass().equals(IPsecTechnologyParameter.class)){
							IPsecTechnologyParameter ipsec_tp = (IPsecTechnologyParameter) tsp;
							if(ipsec_tp.getRemoteEndpoint() != null){
								psaConfigObj.put("right", ipsec_tp.getRemoteEndpoint());
							}
							else{
								System.out.println("ERROR: remoteEndpoint is needed");
							}
							
							if(ipsec_tp.getLocalEndpoint() != null){
								psaConfigObj.put("left", ipsec_tp.getLocalEndpoint());
							}
							else{
								System.out.println("ERROR: localEndpoint is needed");
							}
							
							
						}
						else if(tsp.getClass().equals(IKETechnologyParameter.class)){
							IKETechnologyParameter ike_tp = (IKETechnologyParameter) tsp;
							if(ike_tp.getLifetime() != null){
								defaultConfigObj.put("ikelifetime", ike_tp.getLifetime());
							}
							else{
								System.out.println("ERROR: ikelifetime is needed");
							}
							
							if(ike_tp.getRekeyMargin() != null){
								defaultConfigObj.put("rekeymargin", ike_tp.getRekeyMargin());
							}
							else{
								System.out.println("ERROR: rekeymargin is needed");
							}
							
							if(ike_tp.getKeyringTries() != null){
								defaultConfigObj.put("keyingtries", ike_tp.getKeyringTries());
							}
							else{
								System.out.println("ERROR: keyingtries is needed");
							}
							
							if(ike_tp.getExchangeMode() != null){
								defaultConfigObj.put("keyexchange", ike_tp.getExchangeMode());
							}
							else{
								System.out.println("ERROR: keyexchange is needed");
							}
							
						}
						
					}
					if(action_params.getAdditionalNetworkConfigurationParameters().getClass().equals(RemoteAccessNetworkConfiguration.class)){
						RemoteAccessNetworkConfiguration rnc = (RemoteAccessNetworkConfiguration) action_params.getAdditionalNetworkConfigurationParameters();
						
						if(rnc.getRemoteSubnet() != null){
							psaConfigObj.put("rightsubnet", rnc.getRemoteSubnet());
						}
						else{
							System.out.println("ERROR: rightsubnet is needed");
						}
						if(rnc.getLocalSubnet() != null){
							psaConfigObj.put("leftsubnet", rnc.getLocalSubnet());
						}
						else{
							System.out.println("ERROR: leftsubnet is needed");
						}
						
						if(rnc.getStartIPAddress() != null){
							psaConfigObj.put("leftsourceip", rnc.getStartIPAddress());
						}
						else{
							System.out.println("ERROR: leftsourceip is needed");
						}
						
					}
					if(action_params.getAuthenticationParameters() != null){
						AuthenticationParameters auth_params = action_params.getAuthenticationParameters();
						if(auth_params.getCertFilename() != null){
							psaConfigObj.put("leftcert", auth_params.getCertFilename());
						}
						else{
							System.out.println("ERROR: leftcert is needed");
						}
						
						if(auth_params.getRemoteId() != null){
							psaConfigObj.put("rightid", auth_params.getRemoteId());
						}
						else{
							System.out.println("ERROR: rightid is needed");
						}
						
						if(auth_params.getCertId() != null){
							psaConfigObj.put("leftid", auth_params.getCertId());
						}
						else{
							System.out.println("ERROR: leftid is needed");
						}
					}
					if(dpa.getTechnologyActionSecurityProperty() != null){
						for(TechnologyActionSecurityProperty sec_pty : dpa.getTechnologyActionSecurityProperty()){
							if(sec_pty.getClass().equals(Confidentiality.class)){
								Confidentiality c = (Confidentiality) sec_pty;
								
							}
							else if(sec_pty.getClass().equals(Integrity.class)){
								Integrity i = (Integrity) sec_pty;
								
							}
							else if(sec_pty.getClass().equals(Authentication.class)){
								Authentication auth = (Authentication) sec_pty;
								
							}
						}
						
					}
				}
				
				psaConfigObj.put("auto", "add");
				psaConfigObj.put("leftfirewall", "yes");
				JSONObject obj = new JSONObject();
				obj.put("default", defaultConfigObj);
				obj.put("psa", psaConfigObj);				
				content = obj.toJSONString();
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				JsonParser jp = new JsonParser();
				JsonElement je = jp.parse(content);
				content = gson.toJson(je);
				
				
				

			} catch (JAXBException e) {
				e.printStackTrace();
			}

		} catch (Exception e) {
			result = -2;
			e.printStackTrace();
		}

		try {					
			File confFile = new File(securityControlFileName);
			
			
			try {
				BufferedWriter writer = new BufferedWriter(new FileWriter(confFile));

				writer.write(content);
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
	


}
