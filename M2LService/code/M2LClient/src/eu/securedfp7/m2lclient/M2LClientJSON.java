package eu.securedfp7.m2lclient;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


public class M2LClientJSON {
	public static void main(String[] args) {
		String serviceURL = "http://192.168.2.161:8181/restconf/operations/m2lservice:m2ltranslate";
		//String securityControl = "netfilter";
		String securityControl = "general";
		String MSPL = "<?xml version='1.0'?><MSPL></MSPL>";
		//String input = "{\"input\": {\"mspl_rules\": \""+MSPL+"\",\"security_control\": \""+securityControl+"\"}}";
		
		JSONObject contentObj = new JSONObject();
		contentObj.put("mspl_rules", MSPL);
		contentObj.put("security_control", securityControl);
		JSONObject inputObj = new JSONObject();
		inputObj.put("input", contentObj);
		String input = inputObj.toJSONString();
		
		System.out.println(input);
		
		File configurationFile = new File("/home/mvallini/Desktop/configurationFile.conf");
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+securityControl);
		
		ClientConfig config = new ClientConfig();
		HttpAuthenticationFeature authFeature = HttpAuthenticationFeature.basicBuilder()
			    .nonPreemptive()
			    .credentials("admin", "admin")
			    .build();
		config.register(authFeature);
		Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL);
	    Response response = target.request().accept(MediaType.APPLICATION_JSON).post(Entity.entity(input, MediaType.APPLICATION_JSON));
	    
	    
	    
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

		
		System.out.println("Configuration saved to "+configurationFile.getPath());

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
}
