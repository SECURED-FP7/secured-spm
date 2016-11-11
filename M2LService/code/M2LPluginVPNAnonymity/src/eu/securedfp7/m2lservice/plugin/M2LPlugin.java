package eu.securedfp7.m2lservice.plugin;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Scanner;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.rule.impl.GenericRule;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.AnonimityAction;
import eu.securedfp7.m2lservice.plugin.diff_match_patch.Diff;

public class M2LPlugin {
	private static String securityControl = "Anonymity"; // type of
															// security
															// control,
	// e.g., netfilter, squid
	private static String version = "1.0"; // version
	private static String devlopedBy = "PrimeTel PLC"; // who developed
														// the plugin
	private static String providedBy = "SECURED project"; // who provided the
															// plugin

	public M2LPlugin() {

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
			if (Base64.isBase64(inputString.getBytes())) {
				base64encode = true;
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// if the input file is encoded in base64 we need to convert the file
		if (base64encode) {
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

		try {
			File file = new File(MSPLFileName);

			JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(file);

			String country = getCountry(itResource);
			String confFileString = getConf(country);

			/*
			 * After getting the base64 encoded conf file we decode it.
			 */
			confFileString = new String(Base64.decodeBase64(confFileString)).trim();

//			checkIfEqual(confFileString, country);


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

		// if the input file is encoded in base64 we need to convert the output
		// file to base64
		if (base64encode) {
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

	/**
	 * Testing method used to check that all conf files when retrieved from PSAR and decoded from base64 are the same as the original conf files.
	 * @param decoded The decoded from base64 OpenVPN conf file retrieved from PSAR.
	 * @param country The country selection from MSPL.
	 * @return Boolean. True if the local conf file matches the one decoded from PSAR.
	 */
	private Boolean checkIfEqual(String decoded, String country) {
		String content;
		/*
		 * HashMap to map the country to the original OpenVPN configuration file in order to cross-check that the decoding was correct.
		 * In order to use the paths to the local files must be changed to point to the local file system.
		 */
		
		HashMap<String, String> country_to_conf = new HashMap<String, String>() {
			{
				put("cyprus",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpncyprus/ptlvpn-cy-tcp443udp1194.ovpn");
				put("indonesia",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/tcpvpn/id1-tcpvpn.com-443.ovpn");
				put("singapore",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/tcpvpn/sg1-mct.tcpvpn.com-443.ovpn");
				put("germany",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpnbook/vpnbook-de233-tcp443.ovpn");
				put("usa",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpnbook/vpnbook-us1-tcp443.ovpn");
				put("romania",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpnbook/vpnbook-euro1-tcp443.ovpn");
				put("france",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpnme/vpnme_fr_tcp443.ovpn");
				put("uk",
						"/home/ned/centos_PSA_DEVELOPMENT/PSA_Development/PSA_Anonymity/vpnserver_confs/vpnkeys/uk1.vpnkeys.com.tcp.ovpn");
			}
		};

		try {
			content = new Scanner(new File(country_to_conf.get(country))).useDelimiter("\\Z").next();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			content = "";
		}

		if (decoded.equals(content.trim())) {
			System.out.println("equal");
			return true;
		} else {
			System.out.println("not equal\n\n\n");
			System.out.println("PSAR CONF:" + decoded.length());
			System.out.println(decoded);
			System.out.println("\n\nLOCAL CONF:" + content.length());
			System.out.println(content);
			diff_match_patch difference = new diff_match_patch();
			LinkedList<Diff> deltas = difference.diff_main(decoded.trim(), content.trim());
			for (Diff d : deltas) {
				System.out.println("Delta:" + d.text);
				System.out.println("Delta:" + d.toString());
			}
			return false;
		}

	}

	/**
	 * Parse the MSPL to get the country selection made by the user. If there was an error in parsing the MSPL
	 * we default to return cyprus as the selected country.
	 * 
	 * @return String. returns the country selection.
	 */
	private String getCountry(ITResource itResource) {
		try {
			return ((AnonimityAction) ((RuleSetConfiguration) itResource.getConfiguration()).getConfigurationRule()
					.get(0).getConfigurationRuleAction()).getCountry().get(0);
		} catch (Exception e) {
			System.out.println("Error in parsing MSPL:" + e.getMessage());
			System.out.println("Setting default country: Cyprus");
			return "cyprus";
		}
	}

	/**
	 * This method returns the base64 encoded configuration file of the remote OpenVPN server for
	 * the requested country.
	 * 
	 * @param country
	 *            The country for which the remote OpenVPN server configuration
	 *            must be fetched.
	 * @return String. Base64 encoded OpenVPN server configuration.
	 * @throws JAXBException
	 */
	public String getConf(String country) throws JAXBException {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		URI uri;
		try {
			/*
			 * Preparing the URI to request the configuartion file from PSAR:
			 * 1.PSAR IP: 195.235.93.146:8080
			 * 2.We know beforehand the PSA is Anonymity: /v1/PSA/dyn_conf/anonymity
			 * 3.The location parameter is the one used to distinguish between OpenVPN Servers. Namely, location is country and vice versa.
			 */
			// PSAR TELEFONICA
			uri = new URIBuilder().setScheme("http").setHost("195.235.93.146:8080")
					.setPath("/v1/PSA/dyn_conf/anonimityVPN").setParameter("location", country).build();
			
			// PSAR for Mallorca Demo
			//uri = new URIBuilder().setScheme("http").setHost("147.83.42.137:8080")
			//		.setPath("/v1/PSA/dyn_conf/anonymity").setParameter("location", country).build();
			
			/*
			 * Issuing a GET request to retrieve the correct OpenVPN server configuration.
			 * The response is a json object and the parameter of interest is: dyn_conf which contains the base64 encoded confi file
			 * of the OpenVPN server.
			 */
			HttpGet httpget = new HttpGet(uri);
			CloseableHttpResponse response = httpclient.execute(httpget);
			String json_response = EntityUtils.toString(response.getEntity());
			
			System.out.println("JSON:"+json_response);
			
			/*
			 * Parsing the json response from PSAR to get the dynamic
			 * configuration
			 */
			JSONObject obj = new JSONObject(json_response);
			String conf = obj.getString("dyn_conf");
			return conf;
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		}

		return null;
	}

}