package eu.securedfp7.m2lservice;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.util.List;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.sun.beans.finder.ClassFinder;

@Path("/translate/{securityControl}")
public class Translate {

			@Context ServletContext servletContext;
			@POST
			@Produces(MediaType.APPLICATION_OCTET_STREAM)
			@Consumes(MediaType.APPLICATION_XML)
			public Response translate(String incomingXML, @PathParam("securityControl") String securityControl) {
				
				String absPath = servletContext.getRealPath("/");
				String serviceURL = "http://localhost:8080/M2LPluginService/rest/getplugin";
				
				// retrieving MSPL content as string and add to file
				File msplFile = new File(absPath+"mspl_repository/"+"MSPL.dat");
				try {
					FileOutputStream out = new FileOutputStream(msplFile);
					//out.write(absPath.getBytes());
					out.write(incomingXML.getBytes());
					out.close();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
				// request the plug-in for translation
				File pluginFile = new File(absPath+"downloaded_m2lplugins/general-plugin.jar");
				if(pluginFile.exists())
				{
					pluginFile.delete();
				}
				Client client = ClientBuilder.newClient();
				WebTarget target = client.target(serviceURL+"/"+securityControl);
				Response response = target.request().accept(MediaType.APPLICATION_OCTET_STREAM).get();
				InputStream is = (InputStream)response.getEntity();
				try {
					Files.copy(is, pluginFile.toPath());
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				
				
				// perform translation creating tmp file
				//File configurationFile = this.createDummyFile(absPath+"configurations_repository/"+securityControl+".conf.dat");
				File configurationFile = new File(absPath+"configurations_repository/"+securityControl+".conf.dat");
				if(configurationFile.exists())
				{
					configurationFile.delete();
				}
				
				try {
					
					URL[] classLoaderUrls = new URL[]{new URL("file://"+absPath+"downloaded_m2lplugins/general-plugin.jar")};
					URLClassLoader urlClassLoader = new URLClassLoader(classLoaderUrls);
					Class<?> m2lPlugin = urlClassLoader.loadClass("eu.securedfp7.m2lservice.plugin.M2LPlugin");
					Constructor<?> constructor = m2lPlugin.getConstructor();
			        Object m2lPluginObj = constructor.newInstance();
			        Method method = m2lPlugin.getMethod("getConfiguration", new Class[]{String.class, String.class});
			        method.invoke(m2lPluginObj, msplFile.getAbsolutePath(), configurationFile.getAbsolutePath());
				} catch (MalformedURLException | ClassNotFoundException | NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				// if the file does not exist return error
				if (!configurationFile.exists()) {
				    throw new WebApplicationException(404);
				  }
				
				
				// return the file
				return Response.ok(configurationFile, MediaType.APPLICATION_OCTET_STREAM)
			      .header("Content-Disposition", "attachment; filename=\"" + configurationFile.getName() + "\"" ) //optional
			      .build();
			}
			
			private File createDummyFile(String filename)
			{
				File file = new File(filename);
				
				try {
					FileOutputStream out = new FileOutputStream(file);
					
					byte dummyData[] = new String("Some data...").getBytes();
					out.write(dummyData);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				return file;
			}

}
