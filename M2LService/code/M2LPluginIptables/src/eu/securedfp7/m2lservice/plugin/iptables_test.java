package eu.securedfp7.m2lservice.plugin;


import java.io.File;

import javax.xml.bind.JAXBException;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.utils.PolicyWrapper;

public class iptables_test {
	
	
	public static void main(String[] args) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException, InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException, InvalidNetException, NoExternalDataException {
		
		//String MSPLFileName = "MSPL_filtering1.xml";
		String MSPLFileName = "testiptables.mspl";
		String securityControlFileName = "iptables1.conf";
		
		
		long startTime = System.currentTimeMillis();
		M2LPlugin iptables = new M2LPlugin();
		iptables.getConfiguration(MSPLFileName, securityControlFileName);
		long stopTime = System.currentTimeMillis();
		long elapsedTime = stopTime - startTime;
	    System.out.println(elapsedTime);
	}
}
