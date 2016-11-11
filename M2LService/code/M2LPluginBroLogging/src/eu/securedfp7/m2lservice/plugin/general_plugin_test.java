package eu.securedfp7.m2lservice.plugin;


import java.io.File;

import javax.xml.bind.JAXBException;

public class general_plugin_test {
	
	
	public static void main(String[] args) {
		
		
		//String MSPLFileName = "logging1.xml";
		String MSPLFileName = "MSPL_4fe14072-ff02-4bc4-85e2-5b60c9a94f02_bro_log.xml";
		String securityControlFileName = "logging1.conf";
		
		
		long startTime = System.currentTimeMillis();
		M2LPlugin genericPlugin = new M2LPlugin();
		genericPlugin.getConfiguration(MSPLFileName, securityControlFileName);
		long stopTime = System.currentTimeMillis();
		long elapsedTime = stopTime - startTime;
	    System.out.println(elapsedTime);
	}
}
