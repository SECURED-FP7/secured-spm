package eu.fp7.secured.policy.utils;

import java.io.File;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.ApplicationLayerCondition;
import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.FMR;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringCapability;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.PacketFilterCondition;
import eu.fp7.secured.mspl.Priority;
import eu.fp7.secured.mspl.RuleSetConfiguration;
import eu.fp7.secured.mspl.StatefulCondition;
import eu.fp7.secured.mspl.TimeCondition;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.impl.PolicyImpl;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.rule.action.Action;
import eu.fp7.secured.rule.impl.ConditionClause;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;
import eu.fp7.secured.selector.impl.DirectionSelector;
import eu.fp7.secured.selector.impl.HTTPMethodSelector;
import eu.fp7.secured.selector.impl.InterfaceSelector;
import eu.fp7.secured.selector.impl.IpSelector;
import eu.fp7.secured.selector.impl.PortSelector;
import eu.fp7.secured.selector.impl.ProtocolIDSelector;
import eu.fp7.secured.selector.impl.RateLimitSelector;
import eu.fp7.secured.selector.impl.StandardRegExpSelector;
import eu.fp7.secured.selector.impl.StateSelector;
import eu.fp7.secured.selector.impl.TimeSelector;
import eu.fp7.secured.selector.impl.WeekdaySelector;

public class PolicyWrapper {

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
		selectorTypes.addSelectorType("URL", new StandardRegExpSelector());
		selectorTypes.addSelectorType("Direction", new DirectionSelector());
		selectorTypes.addSelectorType("Time", new TimeSelector());
		selectorTypes.addSelectorType("Weekday", new WeekdaySelector());
		return selectorTypes;
	}

	static public Policy getFilteringPolicy(File policyFile) throws JAXBException, InvalidActionException, IncompatibleResolutionTypeException, InvalidIpAddressException,
			InvalidRangeException, IncompatibleSelectorException, IncompatibleExternalDataException, DuplicateExternalDataException, UnsupportedSelectorException,
			InvalidNetException {

		JAXBContext jaxbContext = JAXBContext.newInstance(ITResource.class);

		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		ITResource itResource = (ITResource) jaxbUnmarshaller.unmarshal(policyFile);

		Action defaultAction = null;

		String action_s = ((FilteringAction) ((RuleSetConfiguration) itResource.getConfiguration()).getDefaultAction()).getFilteringActionType();

		if (action_s.toUpperCase().trim().equals("DENY"))
			defaultAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
		if (action_s.toUpperCase().trim().equals("ALLOW"))
			defaultAction = eu.fp7.secured.rule.action.FilteringAction.ALLOW;
		if (defaultAction == null)
			throw new InvalidActionException();

		PolicyImpl policy = null;

		if (((RuleSetConfiguration) itResource.getConfiguration()).getResolutionStrategy() instanceof FMR)
			policy = new PolicyImpl(new FMRResolutionStrategy(), defaultAction, PolicyType.FILTERING, ((RuleSetConfiguration) itResource.getConfiguration()).getName());
		else
			throw new IncompatibleResolutionTypeException();

		RuleSetConfiguration ruleset = (RuleSetConfiguration) itResource.getConfiguration();

		for (ConfigurationRule rule : ruleset.getConfigurationRule()) {
			

			LinkedHashMap<String, Selector> selectors = new LinkedHashMap<>();

			FilteringConfigurationCondition fcc = (FilteringConfigurationCondition) rule.getConfigurationCondition();

			if (fcc.getPacketFilterCondition() != null) {
				if (fcc.getPacketFilterCondition().getInterface() != null && !fcc.getPacketFilterCondition().getInterface().trim().equals("*")) {
					InterfaceSelector interfaceSelector = new InterfaceSelector();
					for(String interfaceString: fcc.getPacketFilterCondition().getInterface().trim().split(",")){
						interfaceSelector.addRange(interfaceString);
					}
					selectors.put("Interface", interfaceSelector);
				}

				if (fcc.getPacketFilterCondition().getProtocolType() != null && !fcc.getPacketFilterCondition().getProtocolType().trim().equals("*")) {
					ProtocolIDSelector protocolIDSelector = new ProtocolIDSelector();
					for(String protocolString:fcc.getPacketFilterCondition().getProtocolType().trim().split(",")){
						if (protocolString.toLowerCase().trim().equals("tcp"))
							protocolIDSelector.addRange("TCP");
						if (protocolString.toLowerCase().trim().equals("udp"))
							protocolIDSelector.addRange("UDP");
						if (protocolString.toLowerCase().trim().equals("icmp"))
							protocolIDSelector.addRange("ICMP");
					}
					if (protocolIDSelector.isEmpty())
						throw new IncompatibleSelectorException(fcc.getPacketFilterCondition().getProtocolType());
					selectors.put("Protocol", protocolIDSelector);
				}

				if (fcc.getPacketFilterCondition().getDestinationPort() != null && !fcc.getPacketFilterCondition().getDestinationPort().trim().equals("*") && !fcc.getPacketFilterCondition().getDestinationPort().trim().equals("")) {
					PortSelector portSelector = new PortSelector();
					for(String portSelectorString: fcc.getPacketFilterCondition().getDestinationPort().trim().split(","))
						portSelector.addRange(portSelectorString.trim());
					selectors.put("Destination Port", portSelector);
				}

				if (fcc.getPacketFilterCondition().getSourcePort() != null && !fcc.getPacketFilterCondition().getSourcePort().trim().equals("*") && !fcc.getPacketFilterCondition().getSourcePort().trim().equals("")) {
					PortSelector portSelector = new PortSelector();
					for(String portSelectorString: fcc.getPacketFilterCondition().getSourcePort().trim().split(","))
						portSelector.addRange(portSelectorString.trim());
					selectors.put("Source Port", portSelector);
				}

				if (fcc.getPacketFilterCondition().getSourceAddress() != null && !fcc.getPacketFilterCondition().getSourceAddress().trim().equals("*") && !fcc.getPacketFilterCondition().getSourceAddress().trim().equals("")) {
					IpSelector ipSelector = new IpSelector();
					for(String ipSelectorString: fcc.getPacketFilterCondition().getSourceAddress().trim().split(","))
						ipSelector.addRange(ipSelectorString.trim());
					selectors.put("Source Address", ipSelector);
				}

				if (fcc.getPacketFilterCondition().getDestinationAddress() != null && !fcc.getPacketFilterCondition().getDestinationAddress().trim().equals("*") && !fcc.getPacketFilterCondition().getDestinationAddress().trim().equals("")) {
					IpSelector ipSelector = new IpSelector();
					for(String ipSelectorString: fcc.getPacketFilterCondition().getDestinationAddress().trim().split(","))
						ipSelector.addRange(ipSelectorString.trim());
					selectors.put("Destination Address", ipSelector);
				}

			}

			if (fcc.getStatefulCondition() != null) {

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

			if (fcc.getApplicationLayerCondition() != null) {

				if (fcc.getApplicationLayerCondition().getHttpMethod() != null && !fcc.getApplicationLayerCondition().getHttpMethod().trim().equals("*") && !fcc.getApplicationLayerCondition().getHttpMethod().trim().equals("")) {
					HTTPMethodSelector httpMethod = new HTTPMethodSelector();
					for(String httpMethodString: fcc.getApplicationLayerCondition().getHttpMethod().split(","))
						httpMethod.addRange(httpMethodString.trim());
					selectors.put("HttpMethod", httpMethod);
				}

				if (fcc.getApplicationLayerCondition().getURL() != null && !fcc.getApplicationLayerCondition().getURL().trim().equals("*") && !fcc.getApplicationLayerCondition().getURL().trim().equals("")) {
					StandardRegExpSelector url = new StandardRegExpSelector();
					url.addRange(fcc.getApplicationLayerCondition().getURL().trim());
					selectors.put("URL", url);
				}
			}
			
			
			if (fcc.getTimeCondition() != null) {

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

			Action ruleAction = null;

			action_s = ((FilteringAction) rule.getConfigurationRuleAction()).getFilteringActionType();
			if (action_s.toUpperCase().trim().equals("DENY"))
				ruleAction = eu.fp7.secured.rule.action.FilteringAction.DENY;
			if (action_s.toUpperCase().trim().equals("ALLOW"))
				ruleAction = eu.fp7.secured.rule.action.FilteringAction.ALLOW;
			if (ruleAction == null)
				throw new InvalidActionException();

			ConditionClause conditionClause = new ConditionClause(selectors);

			Integer externalData = ((Priority) rule.getExternalData()).getValue().intValue();

			policy.insertRule(new GenericRule(ruleAction, conditionClause, rule.getName()), externalData);
		}

		return policy;

	}

	static public void writeFilteringPolicy(String name, List<GenericRule> rules, FilteringCapability capability, Action defaultAction, String filename) throws JAXBException,
			InvalidActionException {
		ITResource itResource = new ITResource();

		RuleSetConfiguration conf = new RuleSetConfiguration();
		itResource.setConfiguration(conf);

		conf.setName(name);

		FilteringAction allow = new FilteringAction();
		allow.setFilteringActionType("ALLOW");

		FilteringAction deny = new FilteringAction();
		deny.setFilteringActionType("DENY");

		if (defaultAction.equals(eu.fp7.secured.rule.action.FilteringAction.DENY))
			conf.setDefaultAction(deny);
		else if (defaultAction.equals(eu.fp7.secured.rule.action.FilteringAction.ALLOW))
			conf.setDefaultAction(allow);
		else
			throw new InvalidActionException();

		conf.setCapability(capability);

		FMR fmr = new FMR();
		conf.setResolutionStrategy(fmr);
		int i = 1;
		for (GenericRule rule : rules) {
			ConfigurationRule rule1 = new ConfigurationRule();
			FilteringConfigurationCondition fcc = new FilteringConfigurationCondition();
			
			TimeCondition tc = new TimeCondition();
			if (rule.getConditionClause().get("TimeZone") != null)
				tc.setTimeZone(rule.getConditionClause().get("TimeZone").toSimpleString());
			if (rule.getConditionClause().get("Time") != null)
				tc.setTime(rule.getConditionClause().get("Time").toSimpleString());
			if (rule.getConditionClause().get("Weekday") != null)
				tc.setWeekday(rule.getConditionClause().get("Weekday").toSimpleString());
			fcc.setTimeCondition(tc);

			ApplicationLayerCondition alc = new ApplicationLayerCondition();
			if (rule.getConditionClause().get("HttpMethod") != null)
				alc.setHttpMethod(rule.getConditionClause().get("HttpMethod").toSimpleString());
			if (rule.getConditionClause().get("URL") != null){
				alc.setURL(rule.getConditionClause().get("URL").toString());
			}
			fcc.setApplicationLayerCondition(alc);

			StatefulCondition sfc = new StatefulCondition();
			if (rule.getConditionClause().get("RateLimit") != null)
				sfc.setLimitRuleHits(rule.getConditionClause().get("RateLimit").toSimpleString());
			if (rule.getConditionClause().get("StateFul") != null)
				sfc.setState(rule.getConditionClause().get("StateFul").toSimpleString());
			fcc.setStatefulCondition(sfc);
			fcc.setIsCNF(false);

			PacketFilterCondition pfc = new PacketFilterCondition();
			if (rule.getConditionClause().get("Destination Address") != null)
				pfc.setDestinationAddress(rule.getConditionClause().get("Destination Address").toSimpleString());
			if (rule.getConditionClause().get("Destination Port") != null)
				pfc.setDestinationPort(rule.getConditionClause().get("Destination Port").toSimpleString());
			if (rule.getConditionClause().get("Direction") != null)
				pfc.setDirection(rule.getConditionClause().get("Direction").toSimpleString());
			if (rule.getConditionClause().get("Interface") != null)
				pfc.setInterface(rule.getConditionClause().get("Interface").toSimpleString());
			if (rule.getConditionClause().get("Protocol") != null)
				pfc.setProtocolType(rule.getConditionClause().get("Protocol").toSimpleString());
			if (rule.getConditionClause().get("Source Address") != null)
				pfc.setSourceAddress(rule.getConditionClause().get("Source Address").toSimpleString());
			if (rule.getConditionClause().get("Source Port") != null)
				pfc.setSourcePort(rule.getConditionClause().get("Source Port").toSimpleString());
			fcc.setPacketFilterCondition(pfc);
			
			rule1.setConfigurationCondition(fcc);
			
			
			if (rule.getAction().equals(eu.fp7.secured.rule.action.FilteringAction.DENY))
				rule1.setConfigurationRuleAction(deny);
			else if (rule.getAction().equals(eu.fp7.secured.rule.action.FilteringAction.ALLOW))
				rule1.setConfigurationRuleAction(allow);
			else
				throw new InvalidActionException();
			

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
