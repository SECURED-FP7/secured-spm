package eu.fp7.secured.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.policy.anomaly.PolicyAnomaly;
import eu.fp7.secured.policy.anomaly.utils.ConflictType;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.impl.FMRResolutionStrategy;
import eu.fp7.secured.rule.impl.GenericRule;
import eu.fp7.secured.rule.selector.Selector;

public class HTMLView {

	public static void createHTMLView(String filename, Collection<PolicyAnomaly> anomalies, LinkedList<Policy> org_policies, LinkedList<Policy> rec_policy, String type, String h1, String h2) throws IOException, InvalidActionException, NoExternalDataException {
		String report_sting = getHeader();
		report_sting +="<h1> "+h1+" </h1>";
		report_sting +="<HR SIZE=4 WIDTH=100% COLOR=red >"; 
		
		
		report_sting +="<FIELDSET>"
				+ "	<LEGEND>"+h2+"</LEGEND>";
		
				
		report_sting += getPolicyInfoHeader();
		
		int num_r = 0;
		for(Policy p:org_policies){
			num_r += p.getRuleSet().size();
		}
		HashSet<GenericRule> rule_anomalies = new HashSet<>();
		for (PolicyAnomaly anomaly : anomalies) {
			for (GenericRule rule : anomaly.getRule_set()) {
				rule_anomalies.add(rule);
			}
		}
		report_sting += getPolicyInfoBody(org_policies.size(), num_r, anomalies.size(), rule_anomalies.size());
		report_sting += getPolicyInfoFooter();
		report_sting +="</FIELDSET>";
		report_sting +="</br>";
		report_sting +="</br>";
		if(type.equals("SUCAS") || type.equals("SUCAD"))
			report_sting += getPolicyTree(org_policies,"treeview2", "User Policies");
		if(type.equals("MUCA"))
			report_sting += getPolicyTree(org_policies,"treeview2", "User-Stack Policies");
		if(type.equals("REC"))
			report_sting += getPolicyTree(org_policies,"treeview2", "Cooperative Policies");
		report_sting +="</br>";
		report_sting += getConflictTree(anomalies, rec_policy, type);
		report_sting +="</br>";
		if(rec_policy!=null && type.equals("REC"))
			report_sting += getPolicyTree(rec_policy,"treeview3", "Reconciled Policy");
		if(rec_policy!=null && type.equals("MUCA"))
			report_sting += getPolicyTree(rec_policy,"treeview3", "Reconciled Policy (User-Stack)");
		
		report_sting += getFooter();
		
		File logFile = new File(filename);

		BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
		writer.write(report_sting);
		
		writer.close();
		
		
		
	}
	
	private static String getPolicyTree(LinkedList<Policy> policies, String id, String name) {
		String report_sting = getTreeHeader(id, name, "rootfolder");
		for (Policy policy : policies) {
			report_sting += getTreeBodyHeader("POLICY : " + policy.getName()+" ("+policy.getDefaultAction()+")","image");	
			if(policy.getRuleSet().size()==0){
				report_sting += getTreeNode("EMPTY POLICY" ,"none");
			}
			for (GenericRule rule : policy.getRuleSet()) {
				report_sting += getTreeBodyHeader("RULE : " + rule.getName() + " (" + rule.getAction()+ ") ","html");
				report_sting += getTreeNode("ACTION : "+rule.getAction(), "none");
				for(String s:rule.getConditionClause().getSelectorsNames()){
					
					report_sting += getTreeNode(s+" : "+rule.getConditionClause().get(s).toSimpleString(),"none");
					
				}
				report_sting += getTreeBodyFooter();
			}
			report_sting += getTreeBodyFooter();
		}
		report_sting += getTreeFooter();
		return report_sting;
	}



	private static String getConflictTree(Collection<PolicyAnomaly> anomalies, LinkedList<Policy> rec_policy, String type) throws InvalidActionException, NoExternalDataException {
		String report_sting = "";
		if(type.equals("SUCAS") || type.equals("SUCAD"))
			report_sting = getTreeHeader("treeview1","Anomalies", "rootfolder");
		if(type.equals("MUCA"))
			report_sting = getTreeHeader("treeview1","Conflicts", "rootfolder");
		if(type.equals("REC"))
			report_sting = getTreeHeader("treeview1","Conflicts", "rootfolder");
		 
		for (PolicyAnomaly anomaly : anomalies) {
			if (anomaly.getConflict().equals(ConflictType.INCONSISTENT) && (type.equals("REC") || type.equals("MUCA"))){
				
				GenericRule rule = anomaly.getRule_set()[0];
				if(rule.getName().contains("POLICY"))
					report_sting +=  getTreeBodyHeader(rule.getName() + " (" + rule.getAction()+ ") ","html");
				else
					report_sting +=  getTreeBodyHeader("RULE : " +rule.getName() + " (" + rule.getAction()+ ") ","html");
				for(String s:rule.getConditionClause().getSelectorsNames()){						
					report_sting += getTreeNode(s+" : "+rule.getConditionClause().get(s).toSimpleString(),"none");
				}
//				
				report_sting += getTreeBodyHeader("OVERWRITES THE FOLLOWING RULES","pdf");
				if(anomaly.getRule_set().length==1){
					report_sting += getTreeNode("DEFAULT ACTION OF USER POLICY","none");
				}
				for (GenericRule r : Arrays.copyOfRange(anomaly.getRule_set(), 1, anomaly.getRule_set().length)	) {
					report_sting += getTreeBodyHeader(r.getName() + " (" + r.getAction()+ ") ","html");
					for(String s:r.getConditionClause().getSelectorsNames()){						
						report_sting += getTreeNode(s+" : "+r.getConditionClause().get(s).toSimpleString(),"none");
					}
					report_sting += getTreeBodyFooter();
				}
				report_sting += getTreeBodyFooter();
				report_sting += getTreeBodyFooter();
			}
			if (type.equals("SUCAS") || type.equals("SUCAD") ){
				report_sting += getTreeBodyHeader(anomaly.getConflict().toString(),"pdf");
				
				GenericRule composed_Rule = anomaly.getRule_set()[0];
				if (type.equals("SUCAS") && anomaly.getConflict() != ConflictType.n_REDUNDANT && anomaly.getConflict() != ConflictType.n_SHADOWED) {
					Policy p =null;
					for(Policy pp:anomaly.getPolicyList()){
						if(pp.containsRule(anomaly.getRule_set()[0]))
							p=pp;
					}
					composed_Rule = p.getResolutionStrategy().composeRules(	anomaly.getRule_set());
				}
				
				report_sting += getTreeBodyHeader("RESULTING" + " (" + composed_Rule.getAction()+ ") ","html");
				
				String report_sting_temp = "";
				for(String s:composed_Rule.getConditionClause().getSelectorsNames()){
					Selector sel = composed_Rule.getConditionClause().get(s);
					boolean found = true;
					for (GenericRule rule : anomaly.getRule_set()) {
						if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
							found = false;
						}
					}

					if (found)
						report_sting_temp += getTreeNode(s+" : "+composed_Rule.getConditionClause().get(s).toSimpleString(),"none");
				}
				
				if(!report_sting_temp.equals("")){
					report_sting += getTreeBodyHeader("UNION ","none");
					report_sting += report_sting_temp;
					report_sting += getTreeBodyFooter();
				}
				
				report_sting_temp="";
				for(String s:composed_Rule.getConditionClause().getSelectorsNames()){
					Selector sel = composed_Rule.getConditionClause().get(s);
					boolean found = true;
					for (GenericRule rule : anomaly.getRule_set()) {
						if (rule.getConditionClause().get(s)==null || !sel.isEquivalent(rule.getConditionClause().get(s))) {
							found = false;
						}
					}

					if (!found)
						report_sting_temp += getTreeNode(s+" : "+composed_Rule.getConditionClause().get(s).toSimpleString(),"none");
				}
				
				if(!report_sting_temp.equals("")){
					report_sting += getTreeBodyHeader("AREA OF INTERSECTION ","none");
					report_sting += report_sting_temp;
					report_sting += getTreeBodyFooter();
				}
				
				report_sting += getTreeBodyFooter();
				
				for (GenericRule rule : anomaly.getRule_set()) {
					Policy p =null;
					for(Policy pp:anomaly.getPolicyList()){
						if(pp.containsRule(rule)){
							p=pp;
						}
					}
					String node_string = "RULE : "+rule.getName() + " (from policy: " +p.getName();
					
					if(p.getResolutionStrategy() instanceof FMRResolutionStrategy){
						FMRResolutionStrategy fmrres = (FMRResolutionStrategy)p.getResolutionStrategy();
						node_string +=  ", priority = " + fmrres.getExternalData(rule);
					}
					
					node_string += ", enforce action "+ rule.getAction()+ ") ";
					
					report_sting += getTreeBodyHeader(node_string,"html");
					for(String s:rule.getConditionClause().getSelectorsNames()){
						
						report_sting += getTreeNode(s+" : "+rule.getConditionClause().get(s).toSimpleString(),"none");
					}
					report_sting += getTreeBodyFooter();
				}
				report_sting += getTreeBodyFooter();
			}
			
		}
		report_sting += getTreeFooter();
		return report_sting;
	}
	
	private static String getHeader(){
		String header = "<!DOCTYPE html>\n";
		header += "<html>";
		header += "<head>";
		header += "<title></title>";
		header += "<link href=\"kendo.common.min.css\" rel=\"stylesheet\" />";
		header += "<link href=\"kendo.default.min.css\" rel=\"stylesheet\" />";
		header += "<link href=\"kendo.dataviz.min.css\" rel=\"stylesheet\" />";
		header += "<link href=\"kendo.dataviz.default.min.css\" rel=\"stylesheet\" />";
		header += " <script src=\"jquery.min.js\"></script>";
		header += "<script src=\"angular.min.js\"></script>";
		header += "<script src=\"kendo.all.min.js\"></script>";
		header += "<script>";
		header += "$(document).ready(function() {";
		header += "$(\"#treeview1\").kendoTreeView();";
		header += "$(\"#treeview2\").kendoTreeView();";
		header += "$(\"#treeview3\").kendoTreeView();";
		header += "});";
		header += "</script>";
		header += "<style scoped>";
		header += ".demo-section {";
		header += "width: 90%;";
		header += "}";
		header += "#treeview1 .k-sprite {";
		header += "background-image: url(\"coloricons-sprite.png\");";
		header += "}";
		header += ".rootfolder { background-position: 0 0; }";
		header += ".folder { background-position: 0 -16px; }";
		header += ".pdf { background-position: 0 -32px; }";
		header += ".html { background-position: 0 -48px; }";
		header += ".image { background-position: 0 -64px; }";
		header += ".none { background-position: 0 -80px; }";
		header += "#treeview2 .k-sprite {";
		header += "background-image: url(\"coloricons-sprite.png\");";
		header += "}";
		header += ".rootfolder { background-position: 0 0; }";
		header += ".folder { background-position: 0 -16px; }";
		header += ".pdf { background-position: 0 -32px; }";
		header += ".html { background-position: 0 -48px; }";
		header += ".image { background-position: 0 -64px; }";
		header += ".none { background-position: 0 -80px; }";
		header += "#treeview3 .k-sprite {";
		header += "background-image: url(\"coloricons-sprite.png\");";
		header += "}";
		header += ".rootfolder { background-position: 0 0; }";
		header += ".folder { background-position: 0 -16px; }";
		header += ".pdf { background-position: 0 -32px; }";
		header += ".html { background-position: 0 -48px; }";
		header += ".image { background-position: 0 -64px; }";
		header += ".none { background-position: 0 -80px; }";
		header += "</style>";
		header += "</head>";
		header += "<body bgcolor=>";
		return header;
	}
	
	private static String getPolicyInfoHeader(){
		String header = "<div style=\"float:top; margin:10px\">";
		return header;
	}
	
	private static String getPolicyInfoBody(int num_p, int num_r, int num_a, int num_ra){
		
		String header = "<FONT SIZE=+1>";
		header +=	" <B>Number of policies analysed </B>  : "+num_p+"</br>";
		header += "<B>Number of rules analysed </B>  : "+num_r+"</br>";
		header += "<B>Number of anomalys found </B>  : "+num_a+"</br>";
		header += "<B>Number of rules with anomalys </B>  : "+num_ra+"</br>";
		header +="</FONT>";
		return header;
	}
	
	private static String getPolicyInfoFooter(){
		String header = "</div>";
		return header;
	}
	
	private static String getTreeHeader(String id, String text, String image){
		String header = "";
		//		header +="<div id=\"example\" style=\"float:left; margin:10px\">";
		header += "<div class=\"demo-section k-header\" >";
		header += "<ul id=\""+id+"\">";
		header += "<li data-expanded=\"false\">";
		header +=  "<span class=\"k-sprite "+image+"\"></span>"+text;
		header += "<ul>";
		return header;
	}
	
	private static String getTreeBodyHeader(String text, String image){
		String header = "<li data-expanded=\"false\">";
		header +=  "<span class=\"k-sprite "+image+"\"></span>"+text;
		header += "<ul>";
		return header;
	}
	
	private static String getTreeNode(String text, String image){
		String header = "<li data-expanded=\"false\">";
		header +=  "<span class=\"k-sprite "+image+"\"></span>"+text;
		header += "</li>";
		return header;
	}
	
	private static String getTreeBodyFooter(){
		String header = "</li>";
		header += "</ul>";
		return header;
	}
		
	private static String getTreeFooter(){
		String header = "</ul>";
		header += "</li>";
		header += "</ul>";
		header += "</div>";
		header += "</div>";
		return header;
	}
	
	private static String getFooter(){
		String header = "</body>";
		header += "</html> \n";
		
		return header;
	}
}
