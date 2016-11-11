package eu.securedfp7.m2lpluginservice;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

//import org.apache.tomcat.jni.Time;

@Path("/getplugin/{securityControl}")
public class GetPlugin {
	
		HashMap pluginsMap = new HashMap();

		@Context ServletContext servletContext;
		@GET
		@Produces(MediaType.APPLICATION_OCTET_STREAM)
		public Response getPlugin(@PathParam("securityControl") String securityControl) {
			
			// load available plugins
			this.initializePlugins();
			
			/*
			String absPath = servletContext.getRealPath("/");
			
			// retrieving the correct plugin as file
			File pluginFile = new File(absPath+"plugins/general-plugin.jar");
			
			
			// return the file
			return Response.ok(pluginFile, MediaType.APPLICATION_OCTET_STREAM)
		      .header("Content-Disposition", "attachment; filename=\"" + pluginFile.getName() + "\"" ) 
		      .build();
		    */
			
			
			M2LPluginItem plugin = this.getRequiredPlugin(securityControl);
			if(plugin != null){ // plugin exists
				
				//File pluginFile = new File(plugin.getPath());
				File pluginFile = new File(servletContext.getRealPath("/")+plugin.getPath());
				
				return Response.ok(pluginFile, MediaType.APPLICATION_OCTET_STREAM)
					      .header("Content-Disposition", "attachment; filename=\"" + pluginFile.getName() + "\"" ) 
					      .build();
			} else { // plugin does not exist
				
				return null;
			}
			
			
		}
		
		public void initializePlugins(){
			
			// load available plugins
			
			File file = new File(servletContext.getRealPath("/")+"plugins/plugin-repository.xml");
			if(!file.exists()){
				// create file with base plugin
				
				M2LPluginItem generalPlugin = new M2LPluginItem();
				generalPlugin.setName("general-plugin");
				generalPlugin.setSecurityControl("general");
				generalPlugin.setPath(servletContext.getRealPath("/")+"plugins/general-plugin.jar");
				M2LPluginsList plugins = new M2LPluginsList();
				plugins.addPlugin(generalPlugin);
				this.pluginsMap.put("all", generalPlugin);
				try {
					JAXBContext jaxbContext = JAXBContext.newInstance(M2LPluginsList.class);
					Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
					jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
					jaxbMarshaller.marshal(plugins, file);
							 
				      } catch (JAXBException e) {
					e.printStackTrace();
				      }
			} else { // load plugins
				JAXBContext jaxbContext;
				try {
					jaxbContext = JAXBContext.newInstance(M2LPluginsList.class);
					Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
					M2LPluginsList plugins = (M2LPluginsList) jaxbUnmarshaller.unmarshal(file);
					Iterator it = plugins.getPlugins().iterator();
					while(it.hasNext()){
						M2LPluginItem item = (M2LPluginItem) it.next();
						if(!this.pluginsMap.containsKey(item.getSecurityControl())){
							this.pluginsMap.put(item.getSecurityControl(), item);
						}
					}
					
				} catch (JAXBException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				 
				
				
				
			}
			
			
		}
		
		
		private M2LPluginItem getRequiredPlugin(String securityControl){
			M2LPluginItem plugin = null;
			
			if(this.pluginsMap.containsKey(securityControl)){
				plugin = (M2LPluginItem) this.pluginsMap.get(securityControl);
			} 
			
			return plugin;
		}
		
}
