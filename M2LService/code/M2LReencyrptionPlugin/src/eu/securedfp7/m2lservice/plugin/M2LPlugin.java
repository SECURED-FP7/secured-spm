package eu.securedfp7.m2lservice.plugin;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.DuplicatedRuleException;
import eu.fp7.secured.exception.policy.IncompatibleExternalDataException;
import eu.fp7.secured.exception.policy.IncompatibleResolutionTypeException;
import eu.fp7.secured.exception.policy.InvalidActionException;
import eu.fp7.secured.exception.policy.NoExternalDataException;
import eu.fp7.secured.exception.policy.UnmanagedRuleException;
import eu.fp7.secured.exception.rule.IncompatibleSelectorException;
import eu.fp7.secured.exception.rule.InvalidIpAddressException;
import eu.fp7.secured.exception.rule.InvalidNetException;
import eu.fp7.secured.exception.rule.InvalidRangeException;
import eu.fp7.secured.exception.rule.UnsupportedSelectorException;
import eu.fp7.secured.mspl.ConfigurationRule;
import eu.fp7.secured.mspl.FilteringAction;
import eu.fp7.secured.mspl.FilteringConfigurationCondition;
import eu.fp7.secured.mspl.ITResource;
import eu.fp7.secured.mspl.RuleSetConfiguration;
import eu.fp7.secured.policy.anomaly.utils.RuleComparator;
import eu.fp7.secured.policy.impl.Policy;
import eu.fp7.secured.policy.resolution.ResolutionComparison;
import eu.fp7.secured.policy.utils.PolicyWrapper;
import eu.fp7.secured.rule.impl.GenericRule;

import java.io.File;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

import org.apache.commons.codec.binary.Base64;

/**
 * Provides the Medium to Low Level (M2L) translation service for Reencryption.
 * 
 * @author TID 
 * @version 1.0 2016/01/13
 */

public class M2LPlugin {

 private static String securityControl = "reencrypt"; // type of security
              // control,
 // e.g., netfilter, squid
 private static String version = "1.0"; // version
 private static String devlopedBy = "TID"; // who developed
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
  File mspl = new File(MSPLFileName);
  File confFile = new File(securityControlFileName);
  String content = null;
  
  NodeList nList =null;
  Node nNode=null;
  Element eElement=null;
  
  String ciphersServer="";
  String ciphersClient="";
  String sslVersionServer="";
  String sslVersionClient="";
  String reencryptionStrategy="";

  //Rellenar content con la configuracion
  try{
  DocumentBuilderFactory dbFactory 
            = DocumentBuilderFactory.newInstance();
  DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
  Document doc = dBuilder.parse(mspl);
  doc.getDocumentElement().normalize();
         
         
  nList = doc.getElementsByTagName("ciphers-server");
  nNode = nList.item(0);
  if (nNode.getNodeType() == Node.ELEMENT_NODE) {
     eElement = (Element) nNode;
     ciphersServer=eElement.getTextContent();
  }
         
  nList = doc.getElementsByTagName("ciphers-client");
  nNode = nList.item(0);
  if (nNode.getNodeType() == Node.ELEMENT_NODE) {
    eElement = (Element) nNode;
    ciphersClient=eElement.getTextContent();
  }
         
  nList = doc.getElementsByTagName("ssl-version-server");
  nNode = nList.item(0);
  if (nNode.getNodeType() == Node.ELEMENT_NODE) {
    eElement = (Element) nNode;
    sslVersionServer=eElement.getTextContent();
  }
         
  nList = doc.getElementsByTagName("ssl-version-client");
  nNode = nList.item(0);
  if (nNode.getNodeType() == Node.ELEMENT_NODE) {
    eElement = (Element) nNode;
    sslVersionClient=eElement.getTextContent();
  }
         
  nList = doc.getElementsByTagName("additionalNetworkConfigurationParameters");
  nNode = nList.item(0);
         
  if (nNode.getNodeType() == Node.ELEMENT_NODE) {
    eElement = (Element) nNode;
    reencryptionStrategy=eElement.getAttribute("reencryption_strategy");
  }

         
  content = "-T -p 8081 --verify-upstream-cert --upstream-trusted-ca ca.pem ";
         
  content = content + "--ciphers-client " + ciphersClient + " ";
  content = content + "--ciphers-server " + ciphersServer + " ";
  content = content + "--ssl-version-client " + sslVersionClient + " ";
  content = content + "--ssl-version-server " + sslVersionServer + " ";
        
  if(reencryptionStrategy.equals("ONLY-SECURE")){
          
    content = content + "-s mitmdump/scripts/script_secure.py";
           
  } else{
    content = content + "-s mitmdump/scripts/script_mono.py";
  }

  try {
    FileWriter fw = new FileWriter(confFile.getAbsoluteFile());
    BufferedWriter bw = new BufferedWriter(fw);
    bw.write(content);
    bw.close();
   } catch (IOException e) {
    e.printStackTrace();
    result = -1;
   }


   
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
 
  }catch (Exception e){
    e.printStackTrace();
 }

  return result;

 }

 

}
