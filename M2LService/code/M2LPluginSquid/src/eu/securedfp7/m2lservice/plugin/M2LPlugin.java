/*
 * Export as runnable JAR
 */

package eu.securedfp7.m2lservice.plugin;
import mspl_class.ConfigurationRule;
import mspl_class.FilteringAction;
import mspl_class.FilteringConfigurationCondition;
import mspl_class.ITResource;
import mspl_class.RuleSetConfiguration;

import java.io.BufferedReader;
import java.io.File;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;

/**
 * Provides the Medium to Low Level (M2L) translation service for Squid.
 * 
 * @author Genís Riera Pérez (from UPC) 
 * @version 1.2 2015/10/27 ( Fulvio Valenza form Polito)
 */

public class M2LPlugin {

	private static String securityControl = "squid"; // type of security
	// control,
	// e.g., netfilter, squid
	private static String version = "1.2"; // version
	private static String devlopedBy = "UPC"; // who developed
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
	public int getConfiguration(String MSPLFileName,
			String securityControlFileName) {
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

			File mspl = new File(MSPLFileName);
			File confFile = new File(securityControlFileName);

			/**
			 * Default port where Squid will listen for HTTP client requests.
			 */
			String http_port = "3128";
			String https_port = "3129";
			String content = null;
			String urlList = "";
			String regList="";


			try {
				JAXBContext jaxbContext = JAXBContext
						.newInstance(ITResource.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext
						.createUnmarshaller();
				ITResource itResource = (ITResource) jaxbUnmarshaller
						.unmarshal(mspl);

				content = preliminary_declarations(http_port, https_port);
				String default_action = ((FilteringAction) ((RuleSetConfiguration) itResource
						.getConfiguration()).getDefaultAction())
						.getFilteringActionType().toLowerCase();
				RuleSetConfiguration rule_set = (RuleSetConfiguration) itResource
						.getConfiguration();
				for (ConfigurationRule rule : rule_set.getConfigurationRule()) {

					FilteringConfigurationCondition fcc = (FilteringConfigurationCondition) rule
							.getConfigurationCondition();

					/**
					 * regex to add whitespaces between letters and numbers.
					 * 
					 * \D A non-digit: [^0-9] \d A digit: [0-9]
					 * 
					 * This regex is equivalent to: (?<=[^0-9])(?=[0-9])
					 */
					String rule_name = rule.getName().toUpperCase()
							.replaceAll("(?<=\\D)(?=\\d)", " ");

					String prior = rule.getName().replaceAll("[a-zA-Z]", "");
					String http_access_cmd = "http_access";
					content += "# " + rule_name + "\n";

					if (((FilteringAction) rule.getConfigurationRuleAction())
							.getFilteringActionType() != null
							&& !((FilteringAction) rule
									.getConfigurationRuleAction())
									.getFilteringActionType().equals("*")) {
						http_access_cmd += " "
								+ ((FilteringAction) rule
										.getConfigurationRuleAction())
										.getFilteringActionType().toLowerCase();
					} else {
						http_access_cmd += " " + default_action;
					}

					if (fcc.getTimeCondition() != null) {
						String weekday = "";
						if (fcc.getTimeCondition().getWeekday() != null) {
							weekday = fcc.getTimeCondition().getWeekday().replaceAll(",", " ");
							weekday = weekday.toUpperCase();
							weekday = weekday.replaceAll("MON", "M");
							weekday = weekday.replaceAll("TUE", "T");
							weekday = weekday.replaceAll("WED", "W");
							weekday = weekday.replaceAll("THU", "H");
							weekday = weekday.replaceAll("FRI", "F");
							weekday = weekday.replaceAll("SAT", "A");
							weekday = weekday.replaceAll("SUN", "S");
							weekday = weekday.replaceAll(" ", "");
						}
						if (fcc.getTimeCondition().getTime() != null) {
							String time_int = fcc.getTimeCondition().getTime().trim();
							String times[] = time_int.split("-");
							content += "acl TimeRule" + prior + " time " + weekday + " " + times[0].substring(0, 5)  + "-" + times[1].substring(0, 5) + "\n";
							http_access_cmd += " TimeRule"+ prior;
						}

					}

					if (fcc.getApplicationLayerCondition() != null) {
						if (fcc.getApplicationLayerCondition().getHttpMethod() != null
								&& !fcc.getApplicationLayerCondition()
								.getHttpMethod().equals("*")) {
							String http_met = fcc
									.getApplicationLayerCondition()
									.getHttpMethod().replaceAll(",", " ");

							content +="acl HTTPmethod"+ prior+" method " + http_met+ "\n";
							http_access_cmd += " HTTPmethod"+ prior;
						}
						if (fcc.getApplicationLayerCondition().getFileExtension() != null) {
							String extension = fcc.getApplicationLayerCondition().getFileExtension();
							content += "acl BlockExt" + prior + " url_regex -i \\." + extension + "$\n";
							http_access_cmd += " BlockExt" + prior;
						}

					}
					
					if (fcc.getPacketFilterCondition() != null) {
						if (fcc.getPacketFilterCondition().getProtocolType() != null
								&& !fcc.getPacketFilterCondition()
								.getProtocolType().equals("*")) {
							String proto = fcc.getPacketFilterCondition()
									.getProtocolType();
							content += "acl ProtocolType" + prior + " proto " + proto
									+ "\n";
							http_access_cmd += " ProtocolType" + prior;
						}

						if (fcc.getPacketFilterCondition().getDestinationPort() != null
								&& !fcc.getPacketFilterCondition()
								.getDestinationPort().equals("*")) {
							String dst_port = fcc.getPacketFilterCondition()
									.getDestinationPort().replaceAll(",", " ");

							/**
							 * Special case to take into account TODO: Ask if
							 * the following http_acces command is correct
							 * always when dst_port equals to squid_http_port.
							 * Suggestion: Would it be correct if the data model
							 * defines ProtocolType as cache_object instead of
							 * DestinationPort?
							 */
							if (dst_port.equals(http_port)) {
								http_access_cmd += " manager";
							} else {
								content += "acl DestinationPortRule" + prior
										+ " port " + dst_port + "\n";
								http_access_cmd += " DestinationPortRule"
										+ prior;
							}
						}
						/*
						if (fcc.getPacketFilterCondition().getSourcePort() != null
								&& !fcc.getPacketFilterCondition()
										.getSourcePort().equals("*")) {
							String src_port = fcc.getPacketFilterCondition()
									.getSourcePort().replaceAll(",", " ");
							content += "acl SourcePortRule" + prior + " src "
									+ src_port + "\n";
							http_access_cmd += " SourcePortRule" + prior;
						}
						 */
						if (fcc.getPacketFilterCondition()
								.getDestinationAddress() != null
								&& !fcc.getPacketFilterCondition()
								.getDestinationAddress().equals("*")) {
							String dst_addr = fcc.getPacketFilterCondition()
									.getDestinationAddress()
									.replaceAll(",", " ");

							/**
							 * Special case to take into account
							 * */
							if (dst_addr.equals("0.0.0.0/0.0.0.0 ")) {
								dst_addr = "all";
							}

							if (!dst_addr.isEmpty()) {
								content += "acl DestinationAddressRule" + prior
										+ " dst " + dst_addr + "\n";
								http_access_cmd += " DestinationAddressRule"
										+ prior;
							}
						}

						if (fcc.getPacketFilterCondition().getSourceAddress() != null
								&& !fcc.getPacketFilterCondition()
								.getSourceAddress().equals("*")) {
							String src_addr = fcc.getPacketFilterCondition()
									.getSourceAddress().replaceAll(",", " ");

							/**
							 * Special case to take into account
							 */
							if (src_addr.equals("0.0.0.0/0.0.0.0 ")) {
								src_addr = "all";
							}

							if (!src_addr.isEmpty()) {
								content += "acl SourceAddressRule" + prior
										+ " src " + src_addr + "\n";
								http_access_cmd += " SourceAddressRule" + prior;
							}
						}
					}

					if (fcc.getApplicationLayerCondition() != null) {
						if (fcc.getApplicationLayerCondition().getURL() != null
								&& !fcc.getApplicationLayerCondition().getURL()
								.equals("*")) {
							String[] url_list = fcc.getApplicationLayerCondition().getURL()
									.replaceAll("\\*", ".")
									.replaceAll("www", "")
									.split(",");
							String out = "";

							if (url_list.length == 1 && url_list[0].equals("0.0.0.0/0.0.0.0")) {
								out = "all";
							}

							int extra = 0;
							String base_http_access_cmd = http_access_cmd;
							http_access_cmd += "";
							for (String element : url_list) {
								element = element.trim();
								if (element.isEmpty())
									continue;
								if (element.contains("youtube")) {
									out += ".youtube.com .googlevideo.com l.google.com m.youtube.com .youtu.be .ytimg.com ";
								} else if (element.startsWith(".")) {
									out += element + " ";
								} else {
									out += "." + element + " ";
								}
								if (out.length() >= 3500) {
									content += "acl URLRule" + prior + "_" + extra
											+ " dstdomain " + out + "\n";
									urlList += http_access_cmd + " URLRule"
											+ prior + "_" + extra + "\n";
									extra++;
									out = "";
								}
							}
							//comment
							String url = fcc.getApplicationLayerCondition()
									.getURL().replaceAll(",", " ")
									.replaceAll("\\*", "");
							content += "acl URLRule" + prior + " dstdomain "
									+ out + "\n";
							http_access_cmd += " URLRule" + prior+ "\n";
							//comment
						}
					}


					if (fcc.getApplicationLayerCondition() != null) {
						if (fcc.getApplicationLayerCondition().getPhrase() != null
								&& !fcc.getApplicationLayerCondition().getPhrase()
								.equals("*")) {
							String[] reg_list = fcc.getApplicationLayerCondition().getPhrase().split(",");
							String out = "";


							int extra = 0;
							String base_http_access_cmd = http_access_cmd;
							http_access_cmd += "";
							for (String element : reg_list) {
								element = element.trim();
								if (element.isEmpty())
									continue;
								else {								
									content += "acl RegRule" + prior + "_" + extra+ " url_regex -i " + element + "\n";
									regList += http_access_cmd + " RegRule"+ prior + "_" + extra + "\n";
									extra++;								
								}

	
							}
							
						}
					}


					if(! http_access_cmd.equals("http_access deny"))
					content += http_access_cmd + "\n";
					
					if(! urlList.equals("")){
					content += urlList + "\n\n";
					urlList="";
					}
					
					if(! regList.equals("")){
					content += regList + "\n\n";
					regList="";
					}
					
				}

				/**
				 * Output the default final behavior for a Squid safe
				 * configuration
				 */
				content += "# Final rules to keep a safe Squid configuration\n";
				content += "http_access " + default_action + " all\n";
				content += "http_reply_access allow all\n";


			} catch (JAXBException e) {
				e.printStackTrace();
			}

			try {
				FileWriter fw = new FileWriter(confFile.getAbsoluteFile());
				BufferedWriter bw = new BufferedWriter(fw);
				bw.write(content);
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
				result = -1;
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


	/**
	 * Preliminary ACL declarations are needed to configure Squid properly. This
	 * method generates them in order to ensure a well set up for Squid.
	 * 
	 * @param squid_http_port
	 *            Port where Squid will listen for HTTP client requests.
	 * @return The preliminary declarations for Squid configuration.
	 */
	public static String preliminary_declarations(String http_port, String https_port) {
		String prel_decl = null;
		try {
			prel_decl = "### SQUID CONFIGURATION FILE ###\n\n";
			prel_decl += "# Preliminary useful declarations\n\n";
			prel_decl += "# Common useful ACLs\n";

			/**
			 * The following ACL is invalid for Squid. It uses the built-in
			 * keyword all to manage 0.0.0.0/0
			 * 
			 * config_file += "acl all src 0.0.0.0/0.0.0.0\n";
			 */

			prel_decl += "acl localhost src 127.0.0.1\n";
			prel_decl += "acl to_localhost dst 127.0.0.0/8\n";
			//prel_decl += "acl manager proto cache_object\n";
			prel_decl += "\n";
			prel_decl += "# ACLs for  HTTP/1.1 common methods\n";
			/*prel_decl += "acl CONNECT method CONNECT\n";
			prel_decl += "acl GET method GET\n";
			prel_decl += "acl POST method POST\n";
			prel_decl += "acl OPTIONS method OPTIONS\n";
			prel_decl += "acl PUT method PUT\n";
			prel_decl += "acl HEAD method HEAD\n";
			prel_decl += "acl DELETE method DELETE\n";
			prel_decl += "acl TRACE method TRACE\n";
			prel_deticl += "\n";*/
			prel_decl += "# Ensures Squid to listen for HTTP client requests through port "
					+ http_port + "\n";
			// prel_decl += "http_port " + http_port + " intercept\n";
			prel_decl += "http_port " + http_port + " tproxy\n";
			// prel_decl += "https_port " + https_port + " intercept ssl-bump generate-host-certificates=off connection-auth=off cert=/etc/squid3/certs/squid-proxy.crt key=/etc/squid3/certs/squid-proxy.key\n";
			// prel_decl += "https_port " + https_port + " tproxy ssl-bump generate-host-certificates=off connection-auth=off cert=/etc/squid3/certs/squid-proxy.crt key=/etc/squid3/certs/squid-proxy.key\n";
			prel_decl += "https_port " + https_port + " tproxy ssl-bump generate-host-certificates=on cert=/etc/squid3/certs/securedCA.pem dynamic_cert_mem_cache_size=4MB\n";
			prel_decl += "always_direct allow all\n";
			prel_decl += "ssl_bump server-first all\n";
			prel_decl += "sslproxy_flags DONT_VERIFY_PEER\n";
			prel_decl += "sslcrtd_program /usr/lib/squid3/ssl_crtd -s /var/lib/ssl_db -M 4MB sslcrtd_children=8 startup=1 idle=1\n";

			prel_decl += "\n";
		} catch (Exception e) {
			e.printStackTrace();
		}
		return prel_decl;
	}

	// convert InputStream to String
	private static String getStringFromInputStream(InputStream is) {

		BufferedReader br = null;
		StringBuilder sb = new StringBuilder();

		String line;
		try {

			br = new BufferedReader(new InputStreamReader(is));
			while ((line = br.readLine()) != null) {
				sb.append(line);
			}

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return sb.toString();

	}
}
