package eu.securedfp7.m2lservice.plugin;


import java.io.File;

import javax.xml.bind.JAXBException;

public class general_plugin_test {
	
	
	public static void main(String[] args) {
		
		
		//String MSPLFileName = "test_conf.mspl.base64";
		String MSPLFileName = "MSPL_013265b6-e6c9-4411-83f4-a72b5e500c41.xml";
		String securityControlFileName = "test.conf";
		
		
		long startTime = System.currentTimeMillis();
		M2LPlugin genericPlugin = new M2LPlugin();
		genericPlugin.getConfiguration(MSPLFileName, securityControlFileName);
		long stopTime = System.currentTimeMillis();
		long elapsedTime = stopTime - startTime;
	    System.out.println(elapsedTime);
	}
}
