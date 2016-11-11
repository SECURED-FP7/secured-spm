package eu.securedfp7.m2lclient;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

//import org.apache.catalina.WebResource;
//import org.apache.tomcat.util.codec.binary.Base64;
import org.glassfish.jersey.client.ClientConfig;





public class M2LClient {

	public static void main(String[] args) {
		
		//testGeneralPlugin();
		//testIPTablesPlugin("testfiles/msplfiltering.xml", "testfiles/conf_iptables.conf");
		//testSquidPlugin("testfiles/mspl_squid_daughter.xml", "testfiles/conf_squid_daughter.conf");
		//testSquidPlugin("testfiles/mspl_squid_son.xml", "testfiles/conf_squid_son.conf");
		//testSquidPlugin("testfiles/MSPL1.xml", "testfiles/conf_squid_MSPL1.conf");
		//testSquidPlugin("testfiles/MSPL2.xml", "testfiles/conf_squid_MSPL2.conf");
		//testIPTablesPlugin("testfiles/msplfiltering.xml", "testfiles/conf_iptables.conf");
		//testIPTablesPlugin("testfiles/MSPL_filtering1.xml", "testfiles/conf_iptables1.conf");
		
		// ICT
		//testSquidPlugin("testfiles/ICT_mspl_father.xml", "testfiles/ICT_squid_father.conf");
		//testSquidPlugin("testfiles/ICT_mspl_father.xml.base64", "testfiles/ICT_squid_father.conf.base64");
		//testSquidPlugin("testfiles/ICT_mspl_son.xml", "testfiles/ICT_squid_son.conf");
		//testSquidPlugin("testfiles/ICT_mspl_son.xml.base64", "testfiles/ICT_squid_son.conf.base64");
		//testSquidPlugin("testfiles/ICT_mspl_daughter.xml", "testfiles/ICT_squid_daughter.conf");
		//testSquidPlugin("testfiles/ICT_mspl_daughter.xml.base64", "testfiles/ICT_squid_daughter.conf.base64");
		
		//testSquidPlugin("testfiles/ICT_mspl_daughter2.xml.base64", "testfiles/ICT_squid_daughter2.conf.base64");
		
		//testIPTablesPlugin("testfiles/testiptables.mspl", "testfiles/testiptables.conf");
		
		//testDansguardianPlugin("testfiles/MSPL_3966144e-88b9-45f4-a9de-fa73d02a3ed6.xml.base64", "testfiles/dansguardian");
		
		testPlugin("brologging", "testfiles/MSPL/MSPL/MSPL_4fe14072-ff02-4bc4-85e2-5b60c9a94f02_bro_log.xml", "testfiles/MSPL/MSPL/bro_log");
		testPlugin("strongswan", "testfiles/MSPL/MSPL/MSPL_38ec4048-71f1-4867-951b-80ff8acd0b77_corporate_vpn.xml", "testfiles/MSPL/MSPL/corporate_vpn");
		testPlugin("reencryptpsa", "testfiles/MSPL/MSPL/MSPL_4872d27d-2996-47e2-bf75-8d04b6f100c5_reencryption.xml", "testfiles/MSPL/MSPL/reencryption");
		testPlugin("iptables", "testfiles/MSPL/MSPL/MSPL_14000feb-06ab-4e36-9e68-c889832cc947_filtering_L4.xml", "testfiles/MSPL/MSPL/iptables");
		testPlugin("bromalware", "testfiles/MSPL/MSPL/MSPL_a5c42245-fb8f-4433-aa2e-16d944303907_bro_malware.xml", "testfiles/MSPL/MSPL/bro_malware");
		testPlugin("bandwidthcontrol", "testfiles/MSPL/MSPL/MSPL_a8260e45-fabc-4354-adab-2fb1dfae6dfd_reduce_bandwidth.xml", "testfiles/MSPL/MSPL/reduce_bandwidth");
		testPlugin("antiphishingpsa", "testfiles/MSPL/MSPL/MSPL_bc0d74e4-c67b-419b-9f09-4b03b27db7ac_antiphishing.xml", "testfiles/MSPL/MSPL/antiphishing");
		testPlugin("anonimityvpn", "testfiles/MSPL/MSPL/MSPL_ef2358c0-a38c-4d28-ad8a-492926124f2c_anonymity.xml", "testfiles/MSPL/MSPL/anonymity");
		testPlugin("parentalcontrol", "testfiles/MSPL/MSPL/MSPL_f5d2c672-62a4-4083-b776-85170bfb01b3_advance_parental_control.xml", "testfiles/MSPL/MSPL/parental_control");
	}
	
	
	public static void testPlugin(String PSAid, String mspl, String conf){
		String serviceURL = "http://130.192.225.109:8090/M2LServiceCoordinator/rest/translate";
		
		String MSPL = "";
		try {
			//MSPL = readFile(mspl);
			MSPL = new String(Files.readAllBytes(Paths.get(mspl)));
			MSPL = MSPL.replace("\\\"", "\"");
			MSPL = MSPL.replace("\\n", "");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		File configurationFile = new File(conf);
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+PSAid);
		
		ClientConfig config = new ClientConfig();
	    Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL+"/"+PSAid);
	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(MSPL, MediaType.APPLICATION_XML));
	    
		
		InputStream is = (InputStream)response.getEntity();
		
		//String output = getStringFromInputStream(is);
		
		/*
		FileOutputStream out;
		try {
			out = new FileOutputStream(configurationFile);
			byte[] encodedBytes = Base64.encodeBase64(output.getBytes());
			out.write(encodedBytes);
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		
		try {
			Files.copy(is, configurationFile.toPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		System.out.println("Configuration saved to "+configurationFile.getPath());
	}
	
	public static void testDansguardianPlugin(String mspl, String conf){
		//String serviceURL = "http://192.168.2.161:8090/M2LServiceCoordinator/rest/translate";
		//String serviceURL = "http://127.0.0.1:8090/M2LServiceCoordinator/rest/translate";
		String serviceURL = "http://130.192.1.102:8090/M2LServiceCoordinator/rest/translate";
		//String serviceURL = "http://130.192.225.109:8090/M2LServiceCoordinator/rest/translate";
		
		//String PSAid = "PSA-parental-control";
		String PSAid = "dansguardian";
		String MSPL = "";
		try {
			//MSPL = readFile(mspl);
			MSPL = new String(Files.readAllBytes(Paths.get(mspl)));
			MSPL = MSPL.replace("\\\"", "\"");
			MSPL = MSPL.replace("\\n", "");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		File configurationFile = new File(conf);
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+PSAid);
		
		ClientConfig config = new ClientConfig();
	    Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL+"/"+PSAid);
	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(MSPL, MediaType.APPLICATION_XML));
	    
		
		InputStream is = (InputStream)response.getEntity();
		
		//String output = getStringFromInputStream(is);
		
		/*
		FileOutputStream out;
		try {
			out = new FileOutputStream(configurationFile);
			byte[] encodedBytes = Base64.encodeBase64(output.getBytes());
			out.write(encodedBytes);
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		
		try {
			Files.copy(is, configurationFile.toPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		System.out.println("Configuration saved to "+configurationFile.getPath());
	}
	
	public static void testSquidPlugin(String mspl, String conf){
		//String serviceURL = "http://192.168.2.161:8090/M2LServiceCoordinator/rest/translate";
		//String serviceURL = "http://127.0.0.1:8090/M2LServiceCoordinator/rest/translate";
		String serviceURL = "http://130.192.1.102:8090/M2LServiceCoordinator/rest/translate";
		
		//String PSAid = "PSA-parental-control";
		String PSAid = "squid";
		String MSPL = "";
		try {
			//MSPL = readFile(mspl);
			MSPL = new String(Files.readAllBytes(Paths.get(mspl)));
			//MSPL = MSPL.replace("\\\"", "\"");
			//MSPL = MSPL.replace("\\n", "");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		File configurationFile = new File(conf);
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+PSAid);
		
		ClientConfig config = new ClientConfig();
	    Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL+"/"+PSAid);
	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(MSPL, MediaType.APPLICATION_XML));
	    
		
		InputStream is = (InputStream)response.getEntity();
		
		//String output = getStringFromInputStream(is);
		
		/*
		FileOutputStream out;
		try {
			out = new FileOutputStream(configurationFile);
			byte[] encodedBytes = Base64.encodeBase64(output.getBytes());
			out.write(encodedBytes);
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		
		try {
			Files.copy(is, configurationFile.toPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		System.out.println("Configuration saved to "+configurationFile.getPath());
	}
	
	public static void testIPTablesPlugin(String mspl, String conf){
		//String serviceURL = "http://192.168.2.161:8090/M2LServiceCoordinator/rest/translate";
		//String serviceURL = "http://127.0.0.1:8090/M2LServiceCoordinator/rest/translate";
		String serviceURL = "http://130.192.1.102:8090/M2LServiceCoordinator/rest/translate";
		
		String PSAid = "iptables";
		String MSPL = "";
		try {
			//MSPL = readFile(mspl);
			MSPL = new String(Files.readAllBytes(Paths.get(mspl)));
			//MSPL = MSPL.replace("\\\"", "\"");
			//MSPL = MSPL.replace("\\n", "");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		File configurationFile = new File(conf);
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+PSAid);
		
		ClientConfig config = new ClientConfig();
	    Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL+"/"+PSAid);
	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(MSPL, MediaType.APPLICATION_XML));
	    
		
		InputStream is = (InputStream)response.getEntity();
		
		String output = getStringFromInputStream(is);
		
		/*
		FileOutputStream out;
		try {
			out = new FileOutputStream(configurationFile);
			byte[] encodedBytes = Base64.encodeBase64(output.getBytes());
			out.write(encodedBytes);
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		
		try {
			Files.copy(is, configurationFile.toPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		System.out.println("Configuration saved to "+configurationFile.getPath());
	}
	
	public static void testGeneralPlugin(){
		String serviceURL = "http://192.168.2.161:8090/M2LServiceCoordinator/rest/translate";
		
		String PSAid = "psaId";
		String MSPL = "<?xml version=\"1.0\"?>" + "<MSPL></MSPL>";
		
		File configurationFile = new File("/home/mvallini/Desktop/configurationFile.conf");
		if(configurationFile.exists())
		{
			configurationFile.delete();
		}
		
		System.out.println("Connecting to "+serviceURL+" requesting translation for "+PSAid);
		
		ClientConfig config = new ClientConfig();
	    Client client = ClientBuilder.newClient(config);
	    WebTarget target = client.target(serviceURL+"/"+PSAid);
	    Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(MSPL, MediaType.APPLICATION_XML));
	    
		
		InputStream is = (InputStream)response.getEntity();
		try {
			Files.copy(is, configurationFile.toPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		System.out.println("Configuration saved to "+configurationFile.getPath());
	}
	
	/*
	static String readFile(String fileName) throws IOException {
	    BufferedReader br = new BufferedReader(new FileReader(fileName));
	    try {
	        StringBuilder sb = new StringBuilder();
	        String line = br.readLine();

	        while (line != null) {
	            sb.append(line);
	            sb.append("\n");
	            line = br.readLine();
	        }
	        return sb.toString();
	    } finally {
	        br.close();
	    }
	}
	*/
	
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
