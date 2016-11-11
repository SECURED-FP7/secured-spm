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
import java.util.Collections;
import java.util.LinkedList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.codec.binary.Base64;

import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.rule.impl.GenericRule;
import main.java.mspl_class.ITResource;
import main.java.mspl_class.RuleSetConfiguration;
import main.java.mspl_class.ReduceBandwidthAction;

public class M2LPlugin {
	private static String securityControl = "Bandwidth Control"; // type of
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

		/*
		 * Performing the actual construction of the configuration file We
		 * extract the downlink/uplink rate specified by the user in HSPL and we
		 * properly identify the burst and latency. Finally, we pass the correct
		 * configuration inside the pre-defined configuration structure.
		 */
		try {
			File file = new File(MSPLFileName);
			double downlink, uplink;
			/*
			 * Parsing the MSPL file to get the downlink and and uplink rate
			 * specified by the user.
			 */
			JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(file);
			try {
				 downlink = ((ReduceBandwidthAction) ((RuleSetConfiguration) itResource.getConfiguration())
						.getDefaultAction()).getReduceBandwidthActionType().getDownlinkBandwidthValue();
			} catch (Exception e2) {
				downlink = -1;
				System.out.println("Downlink not specified. Setting downlink to -1 to exclude downlink limit configuration.");
			}
			
			try {
				uplink = ((ReduceBandwidthAction) ((RuleSetConfiguration) itResource.getConfiguration())
						.getDefaultAction()).getReduceBandwidthActionType().getUplinkBandwidthValue();
			} catch (Exception e2) {
				uplink = -1;
				System.out.println("Uplink not specified. Setting uplink to -1 to exclude uplink limit configuration.");
			}
			 

			/*
			 * Using the retrieved downlink and uplink to get the proper Linux
			 * tc configuration to configure the PSA.
			 */
			String confFileString = getConf(downlink, uplink);

			/*
			 * Prepare the final configuration file
			 */

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
	 * Returns the proper burst based on the rate. if rate <2MB/s then burst=15K
	 * else burst=30K.
	 * 
	 * @param rate
	 * @return string representation based on the rate.
	 */
	public String getBurst(double rate) {
		if (rate < 2048)
			return "15K";
		else
			return "30K";

	}

	/**
	 * Returns the proper burst based on the rate. if rate <2MB/s then
	 * latency=25ms else latency=30ms.
	 * 
	 * @param rate
	 * @return string representation of latency based on the rate.
	 */
	public String getLatency(double rate) {
		if (rate < 2048)
			return "25ms";
		else
			return "30ms";
	}

	/**
	 * Prepares the Linux tc configuration value. All rate will be set in KB/s.
	 * 
	 * @param downlink:
	 *            the downlink rate to set. -1 for no limit.
	 * @param uplink:
	 *            the uplink rate to set. -1 for no limit.
	 * @return string containing the correct configuration.
	 * @throws JAXBException
	 */
	public String getConf(double downlink, double uplink) throws JAXBException {

		double downlinkRate = -1;
		double uplinkRate = -1;
		String uplinkBurst = "";
		String uplinkLatency = "";
		String downlinkBurst = "";
		String downlinkLatency = "";

		/*
		 * Validating the downlink value. If the value is not a correct double
		 * we default to placing no limit to the downlink rate.
		 */
		try {
			if ((Math.abs(downlink) <= Double.MAX_VALUE) && downlink > 0) {
				downlinkRate = downlink;
				downlinkBurst = getBurst(downlinkRate);
				downlinkLatency = getLatency(downlinkRate);
			} else {
				System.out.println("[Error] Downlink Rate:" + String.valueOf(downlink) + " Defaulting to unlimited");
				downlinkRate = -1;
			}
		} catch (NumberFormatException e) {
			System.out.println("[Error] Downlink Rate:" + String.valueOf(downlink) + " Defaulting to unlimited");
			downlinkRate = -1;
		}

		/*
		 * Validating the uplink value. If the value is not a correct double we
		 * default to placing no limit to the downlink rate.
		 */
		try {
			if ((Math.abs(uplink) <= Double.MAX_VALUE) && uplink > 0) {
				uplinkRate = uplink;
				uplinkBurst = getBurst(uplinkRate);
				uplinkLatency = getLatency(uplinkRate);
			} else {
				System.out.println("[Error] Uplink Rate:" + String.valueOf(uplink) + " Defaulting to unlimited");
				uplinkRate = -1;
			}
		} catch (NumberFormatException e) {
			System.out.println("[Error] Uplink Rate:" + String.valueOf(uplink) + " Defaulting to unlimited");
			uplinkRate = -1;
		}

		return prepareConfiguration(downlinkRate, uplinkRate, uplinkBurst, uplinkLatency, downlinkBurst,
				downlinkLatency);
	}

	/**
	 * Prepares the low level configuration.
	 * 
	 * @param downlinkRate:
	 *            the downlink rate to set in KB/s.
	 * @param uplinkRate:
	 *            the downlink rate to set in KB/s.
	 * @param uplinkBurst:
	 *            the burst value to set for uplink traffic.
	 * @param uplinkLatency:
	 *            the latency value to set for uplink traffic.
	 * @param downlinkBurst:
	 *            the burst value to set for downlink traffic.
	 * @param downlinkLatency:
	 *            the latency value to set for downlink traffic.
	 * @return the string containing the low level configuration.
	 */
	public String prepareConfiguration(double downlinkRate, double uplinkRate, String uplinkBurst, String uplinkLatency,
			String downlinkBurst, String downlinkLatency) {

		/**
		 * Initial lines of the configuration file. If no limits have been
		 * specified these will be the only two lines in the psaconf.
		 */
		String configuration = "#!/bin/bash\nTC=/sbin/tc\n\n";

		/**
		 * If a downlink rate has been specified then we add the required
		 * configuration to the configuration file.
		 */
		if (downlinkRate != -1) {
			configuration += "LAN=eth0\n";
			configuration += "LAN_R=" + String.valueOf(downlinkRate) + "kbps\n";
			configuration += "LAN_B=" + downlinkBurst + "\n";
			configuration += "LAN_L=" + downlinkLatency + "\n";
			configuration += "#Clearing the downlink limits\n";
			configuration += "$TC qdisc del dev $LAN root\n";
			configuration += "#Apply the downlink limits\n";
			configuration += "$TC qdisc add dev $LAN handle 10:0 root tbf rate $LAN_R latency $LAN_L burst $LAN_B\n\n";
		}

		/**
		 * If an uplink rate has been specified then we add the required
		 * configuration to the configuration file.
		 */
		if (uplinkRate != -1) {
			configuration += "WAN=eth1\n";
			configuration += "WAN_R=" + String.valueOf(uplinkRate) + "kbps\n";
			configuration += "WAN_B=" + uplinkBurst + "\n";
			configuration += "WAN_L=" + uplinkLatency + "\n";
			configuration += "#Clearing the uplink limits\n";
			configuration += "$TC qdisc del dev $WAN root\n";
			configuration += "#Apply the downlink limits\n";
			configuration += "$TC qdisc add dev $WAN handle 10:0 root tbf rate $WAN_R latency $WAN_L burst $WAN_B";
		}

		return configuration;

	}

}
