/*
 * Export as runnable JAR
 */

package eu.securedfp7.m2lservice.plugin;

import main.java.mspl_class.ConfigurationRule;
import main.java.mspl_class.FilteringAction;
import main.java.mspl_class.FilteringConfigurationCondition;
import main.java.mspl_class.ICRA;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.LevelType;
import main.java.mspl_class.ParentalControlAction;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.SafeNet;
import main.java.mspl_class.Vancouver;
import main.java.mspl_class.Pics;
import main.java.mspl_class.RSAC;

import java.io.File;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.text.StrSubstitutor;


/**
 * Provides the Medium to Low Level (M2L) translation service for Dansguardian.
 * 
 * @author René Serral (from UPC) 
 * @version 1.2 2015/10/27 ( Fulvio Valenza form Polito)
 */

public class M2LPlugin {

	private static String pics = "ICRAchat = ${ICRAchat}\nICRAmoderatedchat = 1\nICRAlanguagesexual = ${ICRAlanguagesexual}\nICRAlanguageprofanity = 0\n";
	private static String securityControl = "dansguardian"; // type of security
														// control,
	// e.g., netfilter, squid
	private static String version = "1.2"; // version
	private static String devlopedBy = "UPC"; // who developed
	// the plugin
	private static String providedBy = "SECURED project"; // who provided the

	// plugin

	public M2LPlugin() {
		pics = pics + "ICRAlanguagemildexpletives = 1\nICRAnuditygraphic = ${ICRAnuditygraphic}\n";
		pics = pics + "ICRAnuditymalegraphic = 0\nICRAnudityfemalegraphic = 0\nICRAnuditytopless = ${ICRAnuditytopless}\n";
		pics = pics + "ICRAnuditybottoms = ${ICRAnuditybottoms}\nICRAnuditysexualacts = 0\nICRAnudityobscuredsexualacts = 0\nICRAnuditysexualtouching = 0\nICRAnuditykissing = 0\n";
		pics = pics + "ICRAnudityartistic = 1\nICRAnudityeducational = 1\nICRAnuditymedical = 1\nICRAdrugstobacco = 0\n";
		pics = pics + "ICRAdrugsalcohol = ${ICRAdrugsalcohol}\nICRAdrugsuse = ${ICRAdrugsuse}\nICRAgambling = 0\nICRAweaponuse = 0\nICRAintolerance = 0\nICRAbadexample = 0\nICRApgmaterial = 0\n";
		pics = pics + "ICRAviolencerape = 0\nICRAviolencetohumans = 0\nICRAviolencetoanimals = 0\nICRAviolencetofantasy = ${ICRAviolencetofantasy}\n";
		pics = pics + "ICRAviolencekillinghumans = 0\nICRAviolencekillinganimals = 0\nICRAviolencekillingfantasy = 0\nICRAviolenceinjuryhumans = 0\n";
		pics = pics + "ICRAviolenceinjuryanimals = 0\nICRAviolenceinjuryfantasy = 0\nICRAviolenceartisitic = 0\nICRAviolenceeducational = 0\n";
		pics = pics + "ICRAviolencemedical = 0\nICRAviolencesports = 0\nICRAviolenceobjects = 0\n";
		pics = pics + "RSACviolence = ${RSACviolence}\nRSACsex = ${RSACsex}\nRSACnudity = ${RSACnudity}\nRSAClanguage = ${RSAClanguage}\n";
		pics = pics + "evaluWEBrating = ${evaluWEB}\nCyberNOTsex = ${CyberNOTsex}\nCyberNOTother = 3\nSafeSurfprofanity = ${SafeSurfprofanity}\n";
		pics = pics + "SafeSurfheterosexualthemes = ${SafeSurfheterosexualthemes}\nSafeSurfhomosexualthemes = ${SafeSurfhomosexualthemes}\n";
		pics = pics + "SafeSurfnudity = 3\nSafeSurfviolence = ${SafeSurfviolence}\nSafeSurfsexviolenceandprofanity = 3\nSafeSurfintolerance = 3\n";
		pics = pics + "SafeSurfdruguse = ${SafeSurfdruguse}\nSafeSurfotheradultthemes = ${SafeSurfotheradultthemes}\nSafeSurfgambling = ${SafeSurfgambling}\n";
		pics = pics + "SafeSurfagerange = 3\n";
		pics = pics + "Vancouvertolerance = 0\nVancouverviolence = ${Vancouverviolence}\nVancouversex = ${Vancouversex}\n";
		pics = pics + "Weburbiarating = ${Weburbia}\n";
		pics = pics + "Vancouvermulticulturalism = 0\nVancouvereducationalcontent = ${Vancouvereducationalcontent}\nVancouverenvironmentalawareness = 0\n";
		pics = pics + "Vancouverprofanity = ${Vancouverprofanity}\nVancouversafety = 0\nVancouvercanadiancontent = 0\nVancouvercommercialcontent = 0\n";
		pics = pics + "Vancouvergambling = ${Vancouvergambling}\nICECrating = 0\n";
		pics = pics + "SafeNetnudity = 1\nSafeNetsex = 1\nSafeNetviolence = 1\nSafeNetlanguage = 1\nSafeNetgambling = 0\nSafeNetalcoholtobacco = 0";
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
			if (Base64.isBase64(inputString.getBytes())){
				base64encode = true;
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// if the input file is encoded in base64 we need to convert the file
		if (base64encode){
			try {
				String inputString = new String(Files.readAllBytes(Paths.get(MSPLFileName)));
				MSPLFileName = MSPLFileName + ".tmp";
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
		File mspl = new File(MSPLFileName);
		try {
			// File mspl = new File("dansguardian.xml");
			JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
		 	Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(mspl);
				
			ParentalControlAction pacontrol = ((ParentalControlAction)((RuleSetConfiguration)itResource.getConfiguration()).getDefaultAction());
			Pics my_pics = pacontrol.getPics();
			Map<String, String> valuesMap = new HashMap<>();
			ICRA icra = (ICRA)my_pics.getICRA();
			if (icra != null) {
				if (icra.isICRAchat()) {
					 valuesMap.put("ICRAchat", "1");
				} else {
					 valuesMap.put("ICRAchat", "0");
				}
				if (icra.isICRAlanguagesexual()) {
					valuesMap.put("ICRAlanguagesexual", "1");
				} else {
					valuesMap.put("ICRAlanguagesexual", "0");						
				}
				if (icra.isICRAnuditygraphic()) {
					valuesMap.put("ICRAnuditygraphic", "1");						
				} else {
					valuesMap.put("ICRAnuditygraphic", "0");						
				}
				if (icra.isICRAnuditytopless()) {
					valuesMap.put("ICRAnuditytopless", "1");
				} else {
					valuesMap.put("ICRAnuditytopless", "0");						
				}
				if (icra.isICRAnuditybottoms()) {
					valuesMap.put("ICRAnuditybottoms", "1");
				} else {
					valuesMap.put("ICRAnuditybottoms", "0");						
				}
				if (icra.isICRAdrugsuse()) {
					valuesMap.put("ICRAdrugsuse", "1");
				} else {
					valuesMap.put("ICRAdrugsuse", "0");			
				}
				if (icra.isICRAdrugsalcohol()) {
					valuesMap.put("ICRAdrugsalcohol", "1");
				} else {
					valuesMap.put("ICRAdrugsalcohol", "0");						
				}
				if (icra.isICRAviolencetofantasy()) {
					valuesMap.put("ICRAviolencetofantasy", "1");
				} else {
					valuesMap.put("ICRAviolencetofantasy", "0");
				}
			}
			RSAC rsac = (RSAC)my_pics.getRSAC();
			if (rsac != null) {
				valuesMap.put("RSACviolence", "" + rsac.getRSACviolence());
				valuesMap.put("RSACsex", "" + rsac.getRSACsex());
				valuesMap.put("RSACnudity", "" + rsac.getRSACnudity());
				valuesMap.put("RSAClanguage", "" + rsac.getRSAClanguage());
			}
			int ew = my_pics.getEvaluWEB();
			valuesMap.put("evaluWEB", "" + ew);

			int cnot = my_pics.getCyberNOTsex();
			valuesMap.put("CyberNOTsex", "" + cnot);
			
			int wu = my_pics.getWeburbia();
			valuesMap.put("Weburbia", "" + wu);			
			
			Vancouver vanc = (Vancouver)my_pics.getVancouver();
			if (vanc != null) {
				valuesMap.put("Vancouvereducationalcontent", "" + vanc.getVancouvereducationalcontent());
				valuesMap.put("Vancouverviolence", "" + vanc.getVancouverviolence());
				valuesMap.put("Vancouversex", "" + vanc.getVancouversex());
				valuesMap.put("Vancouverprofanity", "" + vanc.getVancouverprofanity());
				valuesMap.put("Vancouvergambling", "" + vanc.getVancouvergambling());
			}

			SafeNet sn = (SafeNet)my_pics.getSafeNet();
			if (vanc != null) {
				valuesMap.put("SafeSurfdruguse", "" + sn.getSafeSurfdruguse());
				valuesMap.put("SafeSurfgambling", "" + sn.getSafeSurfgambling());
				valuesMap.put("SafeSurfheterosexualthemes", "" + sn.getSafeSurfheterosexualthemes());
				valuesMap.put("SafeSurfhomosexualthemes", "" + sn.getSafeSurfhomosexualthemes());
				valuesMap.put("SafeSurfotheradultthemes", "" + sn.getSafeSurfotheradultthemes());
				valuesMap.put("SafeSurfprofanity", "" + sn.getSafeSurfprofanity());
				valuesMap.put("SafeSurfviolence", "" + sn.getSafeSurfviolence());
			}
			
			StrSubstitutor sub = new StrSubstitutor(valuesMap);
		    pics = sub.replace(pics);
		}
		catch (JAXBException e) {
			e.printStackTrace();
		}
		// generate_squid_config(http_port);
		//compress_everything();
		// if the input file is encoded in base64 we need to convert the output file to base64
		File confFile = new File(securityControlFileName);
		try {
			FileWriter fw = new FileWriter(confFile.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(pics);
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
			result = -1;
		}

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

		// try {
		// 	deleteRecursive(new File("etc"));
		// } catch (FileNotFoundException e) {
		// 	e.printStackTrace();
		// }

		return result;
	}
}
