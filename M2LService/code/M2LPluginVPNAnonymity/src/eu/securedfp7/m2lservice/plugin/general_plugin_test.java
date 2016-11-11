package eu.securedfp7.m2lservice.plugin;


import java.io.File;

import javax.xml.bind.JAXBException;

public class general_plugin_test {
	
	
	public static void main(String[] args) {
		
		
		String MSPLFileName = "MSPL_5d91c2ab-314a-456d-b0c0-b700ffaa2632.xml";
		String securityControlFileName = "test_conf";
		
		
		long startTime = System.currentTimeMillis();
		M2LPlugin genericPlugin = new M2LPlugin();
		genericPlugin.getConfiguration(MSPLFileName, securityControlFileName);
		long stopTime = System.currentTimeMillis();
		long elapsedTime = stopTime - startTime;
	    System.out.println(elapsedTime);
	}
}
