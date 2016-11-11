package eu.securedfp7.m2lservicecoordinator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;



@Path("/translate/{PSAid}")
public class Translate {

			@Context ServletContext servletContext;
			@POST
			@Produces(MediaType.APPLICATION_OCTET_STREAM)
			@Consumes(MediaType.APPLICATION_XML)
			public Response translate(String incomingXML, @PathParam("PSAid") String PSAid) {
				
				String host = "localhost:8181";
				String absPath = servletContext.getRealPath("/");
				//String serviceURL = "http://localhost:8080/M2LService/rest/translate";
				String serviceURL = "http://"+host+"/restconf/operations/m2lservice:m2ltranslate";
						
				// get security control for PSAid
				PSAid = PSAid.toLowerCase(); // modified by mvallini on 29-oct-2015
				String securityControl = "general";
				if(PSAid.contains("iptables")){
					securityControl = "iptables";
				}
				if(PSAid.contains("squid")){
					securityControl = "squid";
				}
				if(PSAid.contains("dansguardian")){
					securityControl = "dansguardian";
				}
				if(PSAid.contains("parentalcontrol")){
					securityControl = "dansguardian";
				}
				if(PSAid.contains("parental-control")){
					securityControl = "dansguardian";
				}
				if(PSAid.contains("parental_control")){
					securityControl = "dansguardian";
				}
				if(PSAid.contains("reencryptpsa")){
					securityControl = "reencrypt";
				}
				if(PSAid.contains("brologging")){
					securityControl = "brologging";
				}
				if(PSAid.contains("bromalware")){
					securityControl = "bromalware";
				}
				if(PSAid.contains("bandwidthcontrol")){
					securityControl = "reducebandwidth";
				}
				if(PSAid.contains("antiphishingpsa")){
					securityControl = "antiphishing";
				}
				if(PSAid.contains("strongswan")){
					securityControl = "strongswan";
				}
				if(PSAid.contains("anonimityvpn")){
					securityControl = "anonymity";
				}
				if(PSAid.contains("anonimity")){
					securityControl = "anonymity";
				}
				if(PSAid.contains("anonymity")){
					securityControl = "anonymity";
				}
				if(PSAid.contains("anonymitypsa")){
					securityControl = "anonymity";
				}
				
				
				
				
				// removed for dansguardian
				//incomingXML = incomingXML.replace("\\\"", "\"");
				//incomingXML = incomingXML.replace("\\n", "");
				
				JSONObject contentObj = new JSONObject();
				contentObj.put("mspl_rules", incomingXML);
				contentObj.put("security_control", securityControl);
				JSONObject inputObj = new JSONObject();
				inputObj.put("input", contentObj);
				String input = inputObj.toJSONString();
				
				System.out.println("Connecting to "+serviceURL+" requesting translation for "+securityControl);
				
				//ClientConfig config = new ClientConfig();
			    //Client client = ClientBuilder.newClient(config);
			    //WebTarget target = client.target(serviceURL+"/"+securityControl);
			    //Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(incomingXML, MediaType.APPLICATION_XML));
				
				ClientConfig config = new ClientConfig();
				HttpAuthenticationFeature authFeature = HttpAuthenticationFeature.basicBuilder()
					    .nonPreemptive()
					    .credentials("admin", "admin")
					    .build();
				config.register(authFeature);
				Client client = ClientBuilder.newClient(config);
			    WebTarget target = client.target(serviceURL);
			    Response response = target.request().accept(MediaType.APPLICATION_JSON).post(Entity.entity(input, MediaType.APPLICATION_JSON));
			    
			    File configurationFile = new File(absPath+"conf_"+PSAid);
				if(configurationFile.exists())
				{
					configurationFile.delete();
				}
				
				InputStream is = (InputStream)response.getEntity();
				
				String output = getStringFromInputStream(is);
							
				JSONParser jsonParser = new JSONParser();
				JSONObject jsonObject;
				try {
					jsonObject = (JSONObject) jsonParser.parse(output);	
					JSONObject psaConfigObj = (JSONObject) jsonObject.get("output");
					String psaConfig = (String) psaConfigObj.get("psa_config");
					
					PrintWriter out = new PrintWriter(configurationFile);
					out.println(psaConfig);
					out.close();
					//Files.copy(is, configurationFile.toPath());
					
				} catch (ParseException | FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				/*
				// check if file is zipped
				if(!ZipUtil.isZipFile(configurationFile)){
					// we need to compress the file
					ZipUtil.zipFile(configurationFile, configurationFileZipped);
				} 
				*/
				
				System.out.println("Configuration saved to "+configurationFile.getPath());
								
				
				return Response.ok(configurationFile, MediaType.APPLICATION_OCTET_STREAM)
			      .header("Content-Disposition", "attachment; filename=\"" + configurationFile.getName() + "\"" ) //optional
			      .build();
			}	

			// convert InputStream to String
			private static String getStringFromInputStream(InputStream is) {

				BufferedReader br = null;
				StringBuilder sb = new StringBuilder();

				String line;
				try {

					br = new BufferedReader(new InputStreamReader(is));
					while ((line = br.readLine()) != null) {
						sb.append(line);
					}

				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					if (br != null) {
						try {
							br.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}

				return sb.toString();

			}
	
// OLD
	
//	
//	@Context ServletContext servletContext;
//	@POST
//	@Produces(MediaType.APPLICATION_OCTET_STREAM)
//	@Consumes(MediaType.APPLICATION_XML)
//	public Response translate(String incomingXML, @PathParam("PSAid") String PSAid) {
//		
//		String absPath = servletContext.getRealPath("/");
//		String serviceURL = "http://localhost:8080/M2LService/rest/translate";
//		
//		// get security control for PSAid
//		String securityControl = "general";
//		
//		System.out.println("Connecting to "+serviceURL+" requesting translation for "+securityControl);
//		
//		ClientConfig config = new ClientConfig();
//	    Client client = ClientBuilder.newClient(config);
//	    WebTarget target = client.target(serviceURL+"/"+securityControl);
//	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(incomingXML, MediaType.APPLICATION_XML));
//	    
//	    File configurationFile = new File(absPath+"conf_"+PSAid);
//		if(configurationFile.exists())
//		{
//			configurationFile.delete();
//		}
//		
//		InputStream is = (InputStream)response.getEntity();
//		try {
//			Files.copy(is, configurationFile.toPath());
//		} catch (IOException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
//		
//		/*
//		// check if file is zipped
//		if(!ZipUtil.isZipFile(configurationFile)){
//			// we need to compress the file
//			ZipUtil.zipFile(configurationFile, configurationFileZipped);
//		} 
//		*/
//		
//		System.out.println("Configuration saved to "+configurationFile.getPath());
//						
//		
//		return Response.ok(configurationFile, MediaType.APPLICATION_OCTET_STREAM)
//	      .header("Content-Disposition", "attachment; filename=\"" + configurationFile.getName() + "\"" ) //optional
//	      .build();
//	}	
}

