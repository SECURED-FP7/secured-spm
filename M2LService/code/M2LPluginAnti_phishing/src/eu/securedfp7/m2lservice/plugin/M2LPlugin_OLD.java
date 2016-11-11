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
		if(base64encode) {
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
			} catch (Exception e) {
				result = -2;
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
