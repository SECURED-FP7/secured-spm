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

import org.apache.commons.codec.binary.Base64;


public class M2LPlugin {
	private static String securityControl = "type"; // type of security control,
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
			String confFileString = new String("This file contains specific configuration for the security control\n");	
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
	
	
	/**
	 * Perform the translation
	 * 
	 * @param MSPLFileName
	 *            : MSPL file name
	 * @param securityControlFileName
	 *            : output file
	 * @return
	 */
	/*
	public int getConfiguration(String MSPLFileName,
			String securityControlFileName) {
		int result = 0;

		// internals to provide translation
		FileInputStream in = null;
		FileOutputStream out = null;

		try {
			in = new FileInputStream(MSPLFileName);
			out = new FileOutputStream(securityControlFileName);

			byte[] otherData = new String("This file contains specific configuration for the security control\n").getBytes();
			out.write(otherData);
			
			int c;
			while ((c = in.read()) != -1) {
				out.write(c);
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		return result;
	}
*/


}
