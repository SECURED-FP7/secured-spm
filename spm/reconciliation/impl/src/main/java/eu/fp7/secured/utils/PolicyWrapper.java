/*******************************************************************************
 * Copyright (c) 2015 Politecnico di Torino.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     TorSec - SECURED Team - initial API and implementation
 ******************************************************************************/
package eu.fp7.secured.utils;

import java.awt.Event;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

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
import eu.fp7.secured.mspl.AnonimityAction;
import eu.fp7.secured.mspl.AntiMalwareAction;
import eu.fp7.secured.mspl.AntiMalwareCondition;
import eu.fp7.secured.mspl.ApplicationLayerCondition;
import eu.fp7.secured.mspl.Capability;
import eu.fp7.secured.mspl.CapabilityType;
import eu.fp7.secured.mspl.ConfigurationAction;
import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.DTP;
import eu.fp7.secured.mspl.DataProtectionAction;
import eu.fp7.secured.mspl.DataProtectionCondition;
import eu.fp7.secured.mspl.EnableAction;
import eu.fp7.secured.mspl.EnableActionType;
import eu.fp7.secured.mspl.EventCondition;
import eu.fp7.secured.mspl.FMR;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringCapability;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.HSPL;
import eu.fp7.secured.mspl.HTTPCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.LevelType;
import eu.fp7.secured.mspl.LoggingCapability;
import eu.fp7.secured.mspl.LoggingCondition;
import eu.fp7.secured.mspl.PacketFilterCondition;
import eu.fp7.secured.mspl.ParentalControlAction;
import eu.fp7.secured.mspl.Priority;
import eu.fp7.secured.mspl.ReduceBandwidthAction;
import eu.fp7.secured.mspl.RuleSetConfiguration;
import eu.fp7.secured.mspl.StatefulCondition;
import eu.fp7.secured.mspl.TimeCondition;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.impl.PolicyImpl;
import eu.fp7.secured.policy.resolution.impl.DTPResolutionStrategy;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.policy.utils.SelectorTypes;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.action.DataProtAction;
import eu.fp7.secured.rule.action.LoggingAction;
import eu.fp7.secured.rule.action.ParentalAction;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.selector.impl.DirectionSelector;
import eu.fp7.secured.selector.impl.HTTPMethodSelector;
import eu.fp7.secured.selector.impl.InterfaceSelector;
import eu.fp7.secured.selector.impl.IpSelector;
import eu.fp7.secured.selector.impl.LevelSelector;
import eu.fp7.secured.selector.impl.PortSelector;
import eu.fp7.secured.selector.impl.ProtocolIDSelector;
import eu.fp7.secured.selector.impl.RateLimitSelector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;
import eu.fp7.secured.selector.impl.StateSelector;
import eu.fp7.secured.selector.impl.TimeSelector;
import eu.fp7.secured.selector.impl.WeekdaySelector;
import eu.fp7.secured.xml.Mapping;
import eu.fp7.secured.xml.ServiceGraph;

/**
 * The Class PolicyWrapper.
 */
public class PolicyWrapper {

	/**
	 * Gets the filtering selector types.
	 *
	 * @return the filtering selector types
	 */
	static public SelectorTypes getFilteringSelectorTypes() {
		SelectorTypes selectorTypes = new SelectorTypes();
		selectorTypes.addSelectorType("Destination Address", new IpSelector());
		selectorTypes.addSelectorType("Source Address", new IpSelector());
		selectorTypes.addSelectorType("Destination Port", new PortSelector());
		selectorTypes.addSelectorType("Source Port", new PortSelector());
		selectorTypes.addSelectorType("Interface", new InterfaceSelector());
		selectorTypes.addSelectorType("StateFul", new StateSelector());
		selectorTypes.addSelectorType("RateLimit", new RateLimitSelector());
		selectorTypes.addSelectorType("Protocol", new ProtocolIDSelector());
		
		
		selectorTypes.addSelectorType("HttpMethod", new HTTPMethodSelector());
		selectorTypes.addSelectorType("Browser", new StandardRegExpSelector());
		

		selectorTypes.addSelectorType("UserCert", new StandardRegExpSelector());
		selectorTypes.addSelectorType("CaCert", new StandardRegExpSelector());
		selectorTypes.addSelectorType("RequestMimeType", new StandardRegExpSelector());
		selectorTypes.addSelectorType("ResponseMimeType", new StandardRegExpSelector());
		selectorTypes.addSelectorType("HttpRegexHeader", new StandardRegExpSelector());
		selectorTypes.addSelectorType("HttpStatus", new StandardRegExpSelector());
		selectorTypes.addSelectorType("FileExtension", new StandardRegExpSelector());
		selectorTypes.addSelectorType("MimeType", new StandardRegExpSelector());
		selectorTypes.addSelectorType("MaxConn", new RateLimitSelector());
		selectorTypes.addSelectorType("DstDomain", new StandardRegExpSelector());
		selectorTypes.addSelectorType("SrcDomain", new StandardRegExpSelector());
		
		selectorTypes.addSelectorType("URL", new StandardRegExpSelector());
		selectorTypes.addSelectorType("URLRegex", new StandardRegExpSelector());
		
		selectorTypes.addSelectorType("MimeType", new StandardRegExpSelector());
		selectorTypes.addSelectorType("Phrase", new StandardRegExpSelector());
		
		selectorTypes.addSelectorType("Level", new LevelSelector());
		selectorTypes.addSelectorType("Direction", new DirectionSelector());
		selectorTypes.addSelectorType("Time", new TimeSelector());
		selectorTypes.addSelectorType("Weekday", new WeekdaySelector());
		return selectorTypes;
	}
	
	/**
	 * Gets the service graph.
	 *
	 * @param sgFile the sg file
	 * @return the service graph
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	static public ServiceGraph getServiceGraph(String sgFile) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
	InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
	InvalidNetException, NoExternalDataException, IOException {

		JAXBContext jaxbContext = JAXBContext.newInstance(Mapping.class);
		
		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		
		File logFile = new File("tmp"+sgFile.hashCode());

		BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
		
		writer.write(sgFile);
		
		writer.close();
		
		ServiceGraph sg = ((Mapping)jaxbUnmarshaller.unmarshal(logFile)).getServiceGraph();
		
		logFile.delete();
		
		return sg;
	}
	
	/**
	 * Gets the service graph string.
	 *
	 * @param sgFile the sg file
	 * @return the service graph string
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	static public String getServiceGraphString(Mapping sgFile) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
	InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
	InvalidNetException, NoExternalDataException, IOException {
		
		
		JAXBContext context = JAXBContext.newInstance(Mapping.class);
	    Marshaller m = context.createMarshaller();
	    m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

	    
	    String filename = "tmp"+sgFile.hashCode();
	    File logFile = new File(filename);
	    
	    // Write to System.out
	    m.marshal(sgFile, logFile);
	    
	    String result = "";
	    
	   
		  byte[] encoded = Files.readAllBytes(Paths.get(filename));
		  String s = new String(encoded, Charset.defaultCharset());
		  
		  result =  new String(DatatypeConverter.printBase64Binary(s.getBytes()));
	
	    
	    logFile.delete();
	    
	    
		
		return result;
	}
	
	/**
	 * Gets the IT resource.
	 *
	 * @param policy the policy
	 * @return the IT resource
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	static public ITResource getITResource(String policy) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
	InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
	InvalidNetException, NoExternalDataException, IOException {

		JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
		
		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		
		File logFile = new File("tmp"+policy.hashCode());

		BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
		
		writer.write(policy);
		
		writer.close();
		
		ITResource itr = (ITResource) jaxbUnmarshaller.unmarshal(logFile);
		
		logFile.delete();
		
		return itr;
	}
	
	/**
	 * Read file.
	 *
	 * @param path the path
	 * @param encoding the encoding
	 * @return the string
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	static public  String readFile(String path, Charset encoding) 
			  throws IOException 
			{
			  byte[] encoded = Files.readAllBytes(Paths.get(path));
			  return new String(encoded, encoding);
			}
	
	/**
	 * Gets the policy.
	 *
	 * @param policy the policy
	 * @param creator the creator
	 * @return the policy
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	static public Policy getPolicy(String policy, String creator) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
	InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
	InvalidNetException, NoExternalDataException, IOException {
		
		return getPolicy(getITResource(policy), creator);
	}

	/**
	 * Gets the policy.
	 *
	 * @param policyFile the policy file
	 * @param creator the creator
	 * @return the policy
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 */
	static public Policy getPolicy(File policyFile, String creator) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
		InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
		InvalidNetException, NoExternalDataException {
	
		JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);
		
		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(policyFile);
		
		return getPolicy(itResource, creator);
	}
	
	
	
	/**
	 * Gets the policy.
	 *
	 * @param itResource the it resource
	 * @param creator the creator
	 * @return the policy
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 * @throws IncompatibleResolutionTypeException the incompatible resolution type exception
	 * @throws InvalidIpAddressException the invalid ip address exception
	 * @throws InvalidRangeException the invalid range exception
	 * @throws IncompatibleSelectorException the incompatible selector exception
	 * @throws IncompatibleExternalDataException the incompatible external data exception
	 * @throws DuplicateExternalDataException the duplicate external data exception
	 * @throws UnsupportedSelectorException the unsupported selector exception
	 * @throws InvalidNetException the invalid net exception
	 * @throws NoExternalDataException the no external data exception
	 */
	static public Policy getPolicy(ITResource itResource, String creator) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
	InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
	InvalidNetException, NoExternalDataException {
		Action defaultAction = null;
		Boolean enable = false;
		String MSPL_id = itResource.getID();
		
		ConfigurationAction action = ((RuleSetConfiguration) itResource.getConfiguration()).getDefaultAction();		
		String action_s = "ALLOW";
		if(action instanceof FilteringAction)
			action_s = ((FilteringAction) action).getFilteringActionType();
		
		if(action instanceof AntiMalwareAction)
			action_s = "ALLOW";
		
		if(action instanceof EnableAction){
			defaultAction = new eu.fp7.secured.rule.action.EnableAction(((EnableAction) action).getEnableActionType());
		}
		
		if(action instanceof ParentalControlAction){
			defaultAction = new eu.fp7.secured.rule.action.ParentalAction(((ParentalControlAction) action));
		}
		
		if(action instanceof ReduceBandwidthAction){
			defaultAction = new eu.fp7.secured.rule.action.ReduceBandwidthAction(((ReduceBandwidthAction) action).getReduceBandwidthActionType());
		}

		if(defaultAction==null){
			if (action_s.toUpperCase().trim().equals("DENY"))
				defaultAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
			if (action_s.toUpperCase().trim().equals("ALLOW"))
				defaultAction = eu.fp7.secured.rule.action.FilteringAction.ALLOW;
			if (defaultAction == null)
				throw new InvalidActionException();
		}
		PolicyImpl policy = null;
		

		if (((RuleSetConfiguration) itResource.getConfiguration()).getResolutionStrategy() instanceof FMR)
			policy = new PolicyImpl(new FMRResolutionStrategy(), defaultAction, itResource.getConfiguration().getCapability(), ((RuleSetConfiguration) itResource.getConfiguration()).getName(), creator);
		else if (((RuleSetConfiguration) itResource.getConfiguration()).getResolutionStrategy() instanceof DTP)
			policy = new PolicyImpl(new DTPResolutionStrategy(), defaultAction, itResource.getConfiguration().getCapability(), ((RuleSetConfiguration) itResource.getConfiguration()).getName(), creator);
		else
			policy = new PolicyImpl(new DTPResolutionStrategy(), defaultAction, itResource.getConfiguration().getCapability(), ((RuleSetConfiguration) itResource.getConfiguration()).getName(), creator);

		RuleSetConfiguration ruleset = (RuleSetConfiguration) itResource.getConfiguration();

		for (ConfigurationRule rule : ruleset.getConfigurationRule()) {
			
			
			LinkedHashMap<String, Selector> selectors = new LinkedHashMap<>();

			
			if(rule.getConfigurationCondition() instanceof FilteringConfigurationCondition){
				FilteringConfigurationCondition fcc = (FilteringConfigurationCondition) rule.getConfigurationCondition();
				
				if (fcc!=null && fcc.getPacketFilterCondition() != null) {
					getPacketFilterCondition(selectors, fcc.getPacketFilterCondition());
				}
	
				if (fcc!=null && fcc.getStatefulCondition() != null) {
	
					if (fcc.getStatefulCondition().getState() != null && !fcc.getStatefulCondition().getState().trim().equals("*") && !fcc.getStatefulCondition().getState().trim().equals("")) {
						StateSelector stateSelector = new StateSelector();
						if(fcc.getStatefulCondition().getState().toLowerCase().trim().equals("establishedrelated"))
							stateSelector.addRange("SYN");
						selectors.put("StateFul", stateSelector);
					}
	
					if (fcc.getStatefulCondition().getLimitRuleHits() != null && !fcc.getStatefulCondition().getLimitRuleHits().trim().equals("*") && !fcc.getStatefulCondition().getLimitRuleHits().trim().equals("")) {
						RateLimitSelector rateLimitSelector = new RateLimitSelector();
						rateLimitSelector.addRange(Integer.valueOf(fcc.getStatefulCondition().getLimitRuleHits().trim().split("/")[0]));
						selectors.put("RateLimit", rateLimitSelector);
	
					}
	
				}
	
				if (fcc!=null && fcc.getApplicationLayerCondition() != null) {
					
					if(fcc.getApplicationLayerCondition().getHttpCondition() != null){
						HTTPCondition hc = fcc.getApplicationLayerCondition().getHttpCondition();
						
						if (hc.getHttpMetod() != null && !hc.getHttpMetod().trim().equals("*") && !hc.getHttpMetod().trim().equals("")) {
							HTTPMethodSelector httpMethod = new HTTPMethodSelector();
							for(String httpMethodString: hc.getHttpMetod().split(","))
								httpMethod.addRange(httpMethodString.trim());
							selectors.put("HttpMethod", httpMethod);
						}
						
						if (hc.getBrowser() != null && !hc.getBrowser().trim().equals("*") && !hc.getBrowser().trim().equals("")) {
							StandardRegExpSelector browser = new StandardRegExpSelector();
							for(String browserString: hc.getBrowser().split(","))
								browser.addRange(browserString.trim());
							selectors.put("Browser", browser);
						}
						
						if (hc.getUserCert() != null && !hc.getUserCert().trim().equals("*") && !hc.getUserCert().trim().equals("")) {
							StandardRegExpSelector userCert = new StandardRegExpSelector();
							for(String userCertString: hc.getUserCert().split(","))
								userCert.addRange(userCertString.trim());
							selectors.put("UserCert", userCert);
						}
						
						if (hc.getCaCert() != null && !hc.getCaCert().trim().equals("*") && !hc.getCaCert().trim().equals("")) {
							StandardRegExpSelector caCert = new StandardRegExpSelector();
							for(String caCertString: hc.getCaCert().split(","))
								caCert.addRange(caCertString.trim());
							selectors.put("CaCert", caCert);
						}
						
						if (hc.getRequestMimeType() != null && !hc.getRequestMimeType().trim().equals("*") && !hc.getRequestMimeType().trim().equals("")) {
							StandardRegExpSelector requestMimeType = new StandardRegExpSelector();
							for(String requestMimeTypeString: hc.getRequestMimeType().split(","))
								requestMimeType.addRange(requestMimeTypeString.trim());
							selectors.put("RequestMimeType", requestMimeType);
						}
						
						if (hc.getResponseMimeType() != null && !hc.getResponseMimeType().trim().equals("*") && !hc.getResponseMimeType().trim().equals("")) {
							StandardRegExpSelector responseMimeType = new StandardRegExpSelector();
							for(String responseMimeTypeString: hc.getResponseMimeType().split(","))
								responseMimeType.addRange(responseMimeTypeString.trim());
							selectors.put("ResponseMimeType", responseMimeType);
						}
						
						if (hc.getHttpRegexHeader() != null && !hc.getHttpRegexHeader().trim().equals("*") && !hc.getHttpRegexHeader().trim().equals("")) {
							StandardRegExpSelector httpRegexHeader = new StandardRegExpSelector();
							for(String httpRegexHeaderString: hc.getHttpRegexHeader().split(","))
								httpRegexHeader.addRange(httpRegexHeaderString.trim());
							selectors.put("HttpRegexHeader", httpRegexHeader);
						}
						
						if (hc.getHttpStatus() != null && !hc.getHttpStatus().trim().equals("*") && !hc.getHttpStatus().trim().equals("")) {
							StandardRegExpSelector httpStatus = new StandardRegExpSelector();
							for(String httpStatusString: hc.getHttpStatus().split(","))
								httpStatus.addRange(httpStatusString.trim());
							selectors.put("HttpStatus", httpStatus);
						}
						
					}
	
					if (fcc.getApplicationLayerCondition().getFileExtension() != null && !fcc.getApplicationLayerCondition().getFileExtension().trim().equals("*") && !fcc.getApplicationLayerCondition().getFileExtension().trim().equals("")) {
						StandardRegExpSelector fileExtension = new StandardRegExpSelector();
						for(String string: fcc.getApplicationLayerCondition().getFileExtension().split(",")){
							String s = string.trim();
							s = "\"" + s + "\"";
							fileExtension.addRange(s);
						}
						selectors.put("FileExtension", fileExtension);
					}
					
					if (fcc.getApplicationLayerCondition().getMimeType() != null && !fcc.getApplicationLayerCondition().getMimeType().trim().equals("*") && !fcc.getApplicationLayerCondition().getMimeType().trim().equals("")) {
						StandardRegExpSelector mimeType = new StandardRegExpSelector();
						for(String string: fcc.getApplicationLayerCondition().getMimeType().split(",")){
							String s = string.trim();
							s = "\"" + s + "\"";
							mimeType.addRange(s);
						}
						selectors.put("MimeType", mimeType);
					}
					
					if (fcc.getApplicationLayerCondition().getDstDomain() != null && !fcc.getApplicationLayerCondition().getDstDomain().trim().equals("*") && !fcc.getApplicationLayerCondition().getDstDomain().trim().equals("")) {
						StandardRegExpSelector dstDomain = new StandardRegExpSelector();
						for(String string: fcc.getApplicationLayerCondition().getDstDomain().split(",")){
							String s = string.trim();
							s = "\"" + s + "\"";
							dstDomain.addRange(s);
						}
						selectors.put("DstDomain", dstDomain);
					}
					
					if (fcc.getApplicationLayerCondition().getSrcDomain() != null && !fcc.getApplicationLayerCondition().getSrcDomain().trim().equals("*") && !fcc.getApplicationLayerCondition().getSrcDomain().trim().equals("")) {
						StandardRegExpSelector srcDomain = new StandardRegExpSelector();
						for(String string: fcc.getApplicationLayerCondition().getSrcDomain().split(",")){
							String s = string.trim();
							s = "\"" + s + "\"";
							srcDomain.addRange(s);
						}
						selectors.put("SrcDomain", srcDomain);
					}
					
					if (fcc.getApplicationLayerCondition().getMaxconn() != null) {
						RateLimitSelector maxConn = new RateLimitSelector();
						maxConn.addRange(fcc.getApplicationLayerCondition().getMaxconn());
						selectors.put("MaxConn", maxConn);
					}
	
					if (fcc.getApplicationLayerCondition().getURL() != null && !fcc.getApplicationLayerCondition().getURL().trim().equals("*") && !fcc.getApplicationLayerCondition().getURL().trim().equals("")) {
						StandardRegExpSelector url = new StandardRegExpSelector();
						String s = fcc.getApplicationLayerCondition().getURL().trim();
						s = "\"" + s + "\"";
						url.addRange(s);
//						for(String string: fcc.getApplicationLayerCondition().getURL().split(",")){
//							String s = string.trim();
//							s = "\"" + s + "\"";
//							url.addRange(s);
//						}
						selectors.put("URL", url);
					}
					
					if (fcc.getApplicationLayerCondition().getURLRegex() != null && !fcc.getApplicationLayerCondition().getURLRegex().trim().equals("*") && !fcc.getApplicationLayerCondition().getURLRegex().trim().equals("")) {
						StandardRegExpSelector URLRegex = new StandardRegExpSelector();
						String s = fcc.getApplicationLayerCondition().getURLRegex().trim();
						s = "\"" + s + "\"";
						URLRegex.addRange(s);
//						for(String string: fcc.getApplicationLayerCondition().getURLRegex().split(",")){
//							String s = string.trim();
//							URLRegex.addRange(s);
//						}
						selectors.put("URLRegex", URLRegex);
					}
					
//					if (fcc.getApplicationLayerCondition().getPhrase() != null && !fcc.getApplicationLayerCondition().getPhrase().trim().equals("*") && !fcc.getApplicationLayerCondition().getPhrase().trim().equals("")) {
//						StandardRegExpSelector phrase = new StandardRegExpSelector();
//						String s = fcc.getApplicationLayerCondition().getPhrase().trim();
//						//s = "\"" + s + "\"";
//						phrase.addRange(s);
//						selectors.put("Phrase", phrase);
//					}
					
//					if (fcc.getApplicationLayerCondition().getParentalControlLevel() != null) {
//						LevelSelector level = new LevelSelector();
//						String s = fcc.getApplicationLayerCondition().getParentalControlLevel().toString();
//						level.addRange(s);
//						selectors.put("Level", level);
//					}
				}
				
				
				if (fcc!=null && fcc.getTimeCondition() != null) {
	
					if (fcc.getTimeCondition().getTime() != null && !fcc.getTimeCondition().getTime().trim().equals("*") && !fcc.getTimeCondition().getTime().trim().equals("")) {
						TimeSelector time = new TimeSelector();
						for(String timeString: fcc.getTimeCondition().getTime().split(","))
							time.addRange(timeString.trim());
						selectors.put("Time", time);
					}
	
					if (fcc.getTimeCondition().getWeekday() != null && !fcc.getTimeCondition().getWeekday().trim().equals("*") && !fcc.getTimeCondition().getWeekday().trim().equals("")) {
						WeekdaySelector weekday = new WeekdaySelector();
						for(String weekdayString: fcc.getTimeCondition().getWeekday().split(","))
							weekday.addRange(weekdayString.trim());
						selectors.put("Weekday", weekday);
					}
				}
			}
			
			Action ruleAction = null;
			
			if(rule.getConfigurationCondition() instanceof LoggingCondition){
				LoggingCondition lc = (LoggingCondition) rule.getConfigurationCondition();
	
				if (lc!=null && lc.getPacketCondition().size()!=0) {
					getPacketFilterCondition(selectors, lc.getPacketCondition().get(0));
				}
				
				if (lc!=null && lc.getEventCondition() != null) {
					String event = lc.getEventCondition().getEvents();
					int interval = lc.getEventCondition().getInterval().intValue();
					int threshold = lc.getEventCondition().getThreshold().intValue();
					ruleAction = new LoggingAction(event, interval, threshold);
				}
				
				//beging  new
				if (lc!=null && lc.getApplicationCondition().size() !=0) {
					ApplicationLayerCondition lca=lc.getApplicationCondition().get(0);
					if (lca.getURL() != null && !lca.getURL().trim().equals("*") && !lca.getURL().trim().equals("")) {
						StandardRegExpSelector url = new StandardRegExpSelector();
						String s = lca.getURL().trim();
						s = "\"" + s + "\"";
						url.addRange(s);
//						for(String string: fcc.getApplicationLayerCondition().getURL().split(",")){
//							String s = string.trim();
//							s = "\"" + s + "\"";
//							url.addRange(s);
//						}
						selectors.put("URL", url);
					}
					}
				//end begin new 
			}
			
			if(rule.getConfigurationCondition() instanceof AntiMalwareCondition){
				AntiMalwareCondition ac = (AntiMalwareCondition) rule.getConfigurationCondition();
	
				if (ac!=null && ac.getApplicationLayerCondition() != null) {
					if (ac.getApplicationLayerCondition().getMimeType() != null && !ac.getApplicationLayerCondition().getMimeType().trim().equals("*") && !ac.getApplicationLayerCondition().getMimeType().trim().equals("")) {
						StandardRegExpSelector mimeType = new StandardRegExpSelector();
						for(String httpMethodString: ac.getApplicationLayerCondition().getMimeType().split(","))
							mimeType.addRange(httpMethodString.trim());
						selectors.put("MimeType", mimeType);
					}
				}
				
				
				
			}
			
			
			action = rule.getConfigurationRuleAction();		
			action_s = "DENY";
			if(action == null && ruleAction==null){
				ruleAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
			}
			
			if(action instanceof FilteringAction){
				action_s = ((FilteringAction) action).getFilteringActionType();
				if (action_s.toUpperCase().trim().equals("DENY")){
					ruleAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
				}				
				if (action_s.toUpperCase().trim().equals("ALLOW"))
					ruleAction = eu.fp7.secured.rule.action.FilteringAction.ALLOW;
			}
			
			if(action instanceof DataProtectionAction){
				ruleAction = new DataProtAction((DataProtectionAction)action);
			}
			
			if(action instanceof AntiMalwareAction){
				ruleAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
			}
			
			if(action instanceof ParentalControlAction){
				ruleAction = new ParentalAction((ParentalControlAction)action);
			}
			
			if(action instanceof AnonimityAction){
				ruleAction = new eu.fp7.secured.rule.action.AnonimityAction((AnonimityAction)action);
			}
			
			
			if (ruleAction == null)
				throw new InvalidActionException();

			ConditionClause conditionClause = new ConditionClause(selectors);
			
			HashSet<String> MSPLs = new HashSet<>();
			
			MSPLs.add(MSPL_id);		
			LinkedList<HSPL> HSPLs = new LinkedList<>();
			
			for(HSPL h:rule.getHSPL()){
				HSPLs.add(h);
			}

			GenericRule new_rule = new GenericRule(ruleAction, conditionClause, rule.getName(), MSPLs, HSPLs);
			
			
			
			if (((RuleSetConfiguration) itResource.getConfiguration()).getResolutionStrategy() instanceof FMR){
				Integer externalData = ((Priority) rule.getExternalData()).getValue().intValue();
				policy.insertRule(new_rule, externalData);
			}else{
				policy.insertRule(new_rule);
			}
		}

		
		
		return policy;

	}

	private static void getPacketFilterCondition(LinkedHashMap<String, Selector> selectors, PacketFilterCondition pfc) throws InvalidRangeException,
			IncompatibleSelectorException, InvalidIpAddressException,
			InvalidNetException {
		
			if (pfc.getInterface() != null && !pfc.getInterface().trim().equals("*")) {
				InterfaceSelector interfaceSelector = new InterfaceSelector();
				for(String interfaceString: pfc.getInterface().trim().split(",")){
					interfaceSelector.addRange(interfaceString);
				}
				selectors.put("Interface", interfaceSelector);
			}

			if (pfc.getProtocolType() != null && !pfc.getProtocolType().trim().equals("*")) {
				ProtocolIDSelector protocolIDSelector = new ProtocolIDSelector();
				for(String protocolString:pfc.getProtocolType().trim().split(",")){
					if (protocolString.toLowerCase().trim().equals("tcp"))
						protocolIDSelector.addRange("TCP");
					if (protocolString.toLowerCase().trim().equals("udp"))
						protocolIDSelector.addRange("UDP");
					if (protocolString.toLowerCase().trim().equals("icmp"))
						protocolIDSelector.addRange("ICMP");
				}
				if (protocolIDSelector.isEmpty())
					throw new IncompatibleSelectorException(pfc.getProtocolType());
				selectors.put("Protocol", protocolIDSelector);
			}

			if (pfc.getDestinationPort() != null && !pfc.getDestinationPort().trim().equals("*") && !pfc.getDestinationPort().trim().equals("")) {
				PortSelector portSelector = new PortSelector();
				for(String portSelectorString: pfc.getDestinationPort().trim().split(","))
					portSelector.addRange(portSelectorString.trim());
				selectors.put("Destination Port", portSelector);
			}

			if (pfc.getSourcePort() != null && !pfc.getSourcePort().trim().equals("*") && !pfc.getSourcePort().trim().equals("")) {
				PortSelector portSelector = new PortSelector();
				for(String portSelectorString: pfc.getSourcePort().trim().split(","))
					portSelector.addRange(portSelectorString.trim());
				selectors.put("Source Port", portSelector);
			}

			if (pfc.getSourceAddress() != null && !pfc.getSourceAddress().trim().equals("*") && !pfc.getSourceAddress().trim().equals("") && !pfc.getSourceAddress().trim().equals("0.0.0.0/0") && !pfc.getSourceAddress().trim().equals("0.0.0.0/0.0.0.0")) {
				IpSelector ipSelector = new IpSelector();
				for(String ipSelectorString: pfc.getSourceAddress().trim().split(",")){
					if(!ipSelectorString.trim().equals("0.0.0.0/0.0.0.0") && !ipSelectorString.trim().equals("0.0.0.0/0") && !ipSelectorString.trim().equals("") && !ipSelectorString.trim().equals("*"))
						ipSelector.addRange(ipSelectorString.trim());
				}
				if(!ipSelector.isEmpty())
					selectors.put("Source Address", ipSelector);
			}

			if (pfc.getDestinationAddress() != null && !pfc.getDestinationAddress().trim().equals("*") && !pfc.getDestinationAddress().trim().equals("") && !pfc.getDestinationAddress().trim().equals("0.0.0.0/0") && !pfc.getDestinationAddress().trim().equals("0.0.0.0/0.0.0.0")) {
				IpSelector ipSelector = new IpSelector();
				for(String ipSelectorString: pfc.getDestinationAddress().trim().split(",")){
					if(!ipSelectorString.trim().equals("0.0.0.0/0.0.0.0") && !ipSelectorString.trim().equals("0.0.0.0/0") && !ipSelectorString.trim().equals("") && !ipSelectorString.trim().equals("*"))
						ipSelector.addRange(ipSelectorString.trim());
				}
				if(!ipSelector.isEmpty())
					selectors.put("Destination Address", ipSelector);
			}
	}

	/**
	 * Write policy.
	 *
	 * @param name the name
	 * @param rules the rules
	 * @param capability the capability
	 * @param defaultAction the default action
	 * @param filename the filename
	 * @throws JAXBException the JAXB exception
	 * @throws InvalidActionException the invalid action exception
	 */
	static public void writePolicy(String name, List<GenericRule> rules, List<Capability> capability, Action defaultAction, String filename) throws JAXBException,
			InvalidActionException {
		Boolean reencrypt = false;
		Boolean phishing = false;
		Boolean logging = false;
		Boolean bandwith = false;
		Boolean malware = false;
		Boolean parental = false;
		Boolean ipsec = false;
		Boolean anonimity = false;
		
		ITResource itResource = new ITResource();

		RuleSetConfiguration conf = new RuleSetConfiguration();
		itResource.setConfiguration(conf);

		conf.setName(name);
		itResource.setID(name);

		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");
		
		conf.getCapability().addAll(capability);
		
		for(Capability c:capability){
			if(c.getName() == CapabilityType.REENCRYPT){
				reencrypt = true;
			}
			if(c.getName() == CapabilityType.ANTI_PHISHING){
				phishing = true;
			}
			if(c.getName() == CapabilityType.LOGGING){
				logging = true;
			}
			if(c.getName() == CapabilityType.ADVANCED_PARENTAL_CONTROL){
				parental = true;
			}
			if(c.getName() == CapabilityType.REDUCE_BANDWIDTH){
				bandwith = true;
			}
			if(c.getName() == CapabilityType.OFFLINE_MALWARE_ANALYSIS){
				malware = true;
			}
			if(c.getName() == CapabilityType.IP_SEC_PROTOCOL){
				ipsec = true;
			}
			if(c.getName() == CapabilityType.ANONIMITY){
				anonimity = true;
			}
		}

		if(parental){
			conf.setDefaultAction(((eu.fp7.secured.rule.action.ParentalAction)defaultAction).getAction());
		} else if (reencrypt){
			//no action
		} else if (ipsec){
			//no action
		} else if (anonimity){
			//no action
		}else if (malware){
			AntiMalwareAction a = new AntiMalwareAction();
			a.setAntiMalwareActionType("");
			conf.setDefaultAction(a);
		} else if (logging){
			eu.fp7.secured.mspl.LoggingAction a = new eu.fp7.secured.mspl.LoggingAction();
			a.setLoggingActionType("log_connection");
			conf.setDefaultAction(a);
		} else if (bandwith){
			ReduceBandwidthAction action = new ReduceBandwidthAction();
			action.setReduceBandwidthActionType(((eu.fp7.secured.rule.action.ReduceBandwidthAction)defaultAction).getActionType());
			conf.setDefaultAction(action);
		} else if (phishing){
			EnableAction action = new EnableAction();
			action.setEnableActionType(((eu.fp7.secured.rule.action.EnableAction)defaultAction).getActionType());
			conf.setDefaultAction(action);
		}else {
			if (defaultAction.equals(eu.fp7.secured.rule.action.FilteringAction.DENY))
				conf.setDefaultAction(deny);
			else if (defaultAction.equals(eu.fp7.secured.rule.action.FilteringAction.ALLOW))
				conf.setDefaultAction(allow);
			else
				throw new InvalidActionException();
		}

		

		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		int i = 1;
		for (GenericRule rule : rules) {
			ConfigurationRule rule1 = new ConfigurationRule();
			FilteringConfigurationCondition fcc = new FilteringConfigurationCondition();
			LoggingCondition lc = new LoggingCondition();
			DataProtectionCondition dpc= new DataProtectionCondition();
			AntiMalwareCondition amc = new AntiMalwareCondition();
			
			TimeCondition tc = new TimeCondition();
			Boolean tcb = false;
			if (rule.getConditionClause().get("TimeZone") != null){
				tc.setTimeZone(rule.getConditionClause().get("TimeZone").toSimpleString());
				tcb = true;
			}
			if (rule.getConditionClause().get("Time") != null){
				tc.setTime(rule.getConditionClause().get("Time").toSimpleString());
				tcb = true;
			}
			if (rule.getConditionClause().get("Weekday") != null){
				tc.setWeekday(rule.getConditionClause().get("Weekday").toSimpleString());
				tcb = true;
			}
			if(tcb)
				fcc.setTimeCondition(tc);

			ApplicationLayerCondition alc = new ApplicationLayerCondition();
			Boolean alcb = false;
			if (rule.getConditionClause().get("URL") != null){
				alc.setURL(rule.getConditionClause().get("URL").toString());
				alcb = true;
			}
			if (rule.getConditionClause().get("URLRegex") != null){
				alc.setURLRegex(rule.getConditionClause().get("URLRegex").toString().replace(".", "\\."));
				alcb = true;
			}
			if (rule.getConditionClause().get("FileExtension") != null){
				alc.setFileExtension(rule.getConditionClause().get("FileExtension").toString().replace(".", "\\."));
				alcb = true;
			}
			if (rule.getConditionClause().get("MimeType") != null){
				alc.setMimeType(rule.getConditionClause().get("MimeType").toString().replace(".", "\\."));
				alcb = true;
			}
			if (rule.getConditionClause().get("MaxConn") != null){
				int maxConn = 0;
				String s = rule.getConditionClause().get("MaxConn").toSimpleString().split("/")[0];
				maxConn = new Integer(s);
				alc.setMaxconn(maxConn);
				alcb = true;
			}
			if (rule.getConditionClause().get("DstDomain") != null){
				alc.setDstDomain(rule.getConditionClause().get("DstDomain").toString().replace(".", "\\."));
				alcb = true;
			}
			if (rule.getConditionClause().get("SrcDomain") != null){
				alc.setSrcDomain(rule.getConditionClause().get("SrcDomain").toString().replace(".", "\\."));
				alcb = true;
			}
//			if (rule.getConditionClause().get("Phrase") != null){
//				alc.setPhrase(rule.getConditionClause().get("Phrase").toString().replace(".", "\\."));
//				alcb = true;
//			}
//			if (rule.getConditionClause().get("Level") != null){
//				String level = rule.getConditionClause().get("Level").toSimpleString();
//				
//				if(level.toUpperCase().equals("ADOLESCENT"))
//					alc.setParentalControlLevel(LevelType.ADOLESCENT);
//				if(level.toUpperCase().equals("CHILD"))
//					alc.setParentalControlLevel(LevelType.CHILD);
//				if(level.toUpperCase().equals("PGR"))
//					alc.setParentalControlLevel(LevelType.PGR);
//				if(level.toUpperCase().equals("UNIVERSAL"))
//					alc.setParentalControlLevel(LevelType.UNIVERSAL);
//						
//				alcb = true;
//			}
			
			HTTPCondition hc = new HTTPCondition();
			Boolean hcb = false;
			
			if (rule.getConditionClause().get("HttpMethod") != null){
				hc.setHttpMetod(rule.getConditionClause().get("HttpMethod").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("Browser") != null){
				hc.setBrowser(rule.getConditionClause().get("Browser").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("UserCert") != null){
				hc.setUserCert(rule.getConditionClause().get("UserCert").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("CaCert") != null){
				hc.setCaCert(rule.getConditionClause().get("CaCert").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("RequestMimeType") != null){
				hc.setRequestMimeType(rule.getConditionClause().get("RequestMimeType").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("ResponseMimeType") != null){
				hc.setResponseMimeType(rule.getConditionClause().get("ResponseMimeType").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("HttpRegexHeader") != null){
				hc.setHttpRegexHeader(rule.getConditionClause().get("HttpRegexHeader").toSimpleString());
				hcb = true;
			}
			if (rule.getConditionClause().get("HttpStatus") != null){
				hc.setHttpStatus(rule.getConditionClause().get("HttpStatus").toSimpleString());
				hcb = true;
			}
			
			if(hcb){
				alc.setHttpCondition(hc);
				alcb = true;
			}
			
			if(alcb && !malware)
				fcc.setApplicationLayerCondition(alc);
			if(alcb && malware){
				amc.setApplicationLayerCondition(alc);
			}

			StatefulCondition sfc = new StatefulCondition();
			Boolean sfcb = false;
			if (rule.getConditionClause().get("RateLimit") != null){
				sfc.setLimitRuleHits(rule.getConditionClause().get("RateLimit").toSimpleString());
				sfcb = true;
			}
			if (rule.getConditionClause().get("StateFul") != null){
				sfc.setState(rule.getConditionClause().get("StateFul").toSimpleString());
				sfcb = true;
			}
			if(sfcb)
				fcc.setStatefulCondition(sfc);
			fcc.setIsCNF(false);

			PacketFilterCondition pfc = new PacketFilterCondition();
			Boolean pfcb = false;
			if (rule.getConditionClause().get("Destination Address") != null){
				pfc.setDestinationAddress(rule.getConditionClause().get("Destination Address").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Destination Port") != null){
				pfc.setDestinationPort(rule.getConditionClause().get("Destination Port").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Direction") != null){
				pfc.setDirection(rule.getConditionClause().get("Direction").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Interface") != null){
				pfc.setInterface(rule.getConditionClause().get("Interface").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Protocol") != null){
				pfc.setProtocolType(rule.getConditionClause().get("Protocol").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Source Address") != null){
				pfc.setSourceAddress(rule.getConditionClause().get("Source Address").toSimpleString());
				pfcb = true;
			}
			if (rule.getConditionClause().get("Source Port") != null){
				pfc.setSourcePort(rule.getConditionClause().get("Source Port").toSimpleString());
				pfcb = true;
			}
			if(pfcb && !logging && !ipsec)
				fcc.setPacketFilterCondition(pfc);
			if(logging){
				if(pfcb)
				lc.getPacketCondition().add(pfc);
				if(alcb)
				lc.getApplicationCondition().add(alc);
			}if(pfcb && ipsec){
				dpc.setPacketFilterCondition(pfc);
			}
			
			if(!logging && !malware && !phishing && !parental && !reencrypt && !bandwith && !ipsec && !anonimity)
				rule1.setConfigurationCondition(fcc);
			if(logging)
				rule1.setConfigurationCondition(lc);
			if(ipsec)
				rule1.setConfigurationCondition(dpc);
			
			rule1.getHSPL().addAll(rule.getHSPLs());			
			
			
			if(parental){
				//no action
			} else if(ipsec){
				rule1.setConfigurationRuleAction(((DataProtAction)rule.getAction()).getAction());
			} else if (reencrypt){
				rule1.setConfigurationRuleAction(((DataProtAction)rule.getAction()).getAction());
			} else if (malware){
				//rule1.setConfigurationRuleAction(new AntiMalwareAction());
				rule1.setConfigurationCondition(amc);
			} else if (phishing){
				//do nothing
			} else if (bandwith){
				//do nothing
			} else if (anonimity){
				rule1.setConfigurationRuleAction(((eu.fp7.secured.rule.action.AnonimityAction)rule.getAction()).getAction());
			} else if (logging){
				LoggingAction la = (LoggingAction)rule.getAction();
				EventCondition ec = new EventCondition();
				ec.setEvents(la.getEvent());
				ec.setInterval(new BigInteger(Integer.toString(la.getInterval())));
				ec.setThreshold(new BigInteger(Integer.toString(la.getThreshold())));
				lc.setEventCondition(ec);
			}else {
				if (rule.getAction().equals(eu.fp7.secured.rule.action.FilteringAction.DENY))
					rule1.setConfigurationRuleAction(deny);
				else if (rule.getAction().equals(eu.fp7.secured.rule.action.FilteringAction.ALLOW))
					rule1.setConfigurationRuleAction(allow);
				else{
					System.err.println(rule.getAction());
					throw new InvalidActionException();
				}
			}

			Priority ed1 = new Priority();

			ed1.setValue(new BigInteger(Integer.toString(i++)));
			rule1.setExternalData(ed1);
			rule1.setIsCNF(false);
			rule1.setName(rule.getName());
			conf.getConfigurationRule().add(rule1);
		}
		// create JAXB context and instantiate marshaller
		JAXBContext context = JAXBContext.newInstance(ITResource.class);
		Marshaller m = context.createMarshaller();
		m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

		File file = new File(filename);

		// Write to System.out
		m.marshal(itResource, file);
	}

}
