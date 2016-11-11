package eu.securedfp7.m2lservice.tester;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;

public class M2LPluginTester {

	public static void main(String[] args) {
		if(args.length != 3){
			
			System.out.println("Syntax error: this program requires 3 parameters");
			System.out.println("Program syntax: java -jar M2LPluginTester m2lplugin.jar msplfile configurationfile");
			System.out.println("");
			System.out.println("Where:");
			System.out.println("m2lplugin.jar is the JAR file of the plugin to test, e.g. general-plugin.jar");
			System.out.println("msplfile is the MSPL configuration file (i.e. input file), e.g. psa1.mspl.xml");
			System.out.println("configurationfile is the low-level configuration (i.e. output file), e.g. psa1.conf");
			
		} else {
			
			String pluginFileName = args[0];
			String msplFileName = args[1];
			String configurationFileName = args[2];
			Path currentRelativePath = Paths.get("");
			String absPath = currentRelativePath.toAbsolutePath().toString()+"/"; 
			
			System.out.println("Testing plugin "+absPath+pluginFileName);
			System.out.println("msplfile: "+absPath+msplFileName);
			System.out.println("configurationfile: "+absPath+configurationFileName);
			
			try {
				
				File msplFile = new File(absPath+msplFileName);
				File configurationFile = new File(absPath+configurationFileName);
				if(configurationFile.exists())
				{
					configurationFile.delete();
				}
				
				URL[] classLoaderUrls = new URL[]{new URL("file://"+absPath+pluginFileName)};
				URLClassLoader urlClassLoader = new URLClassLoader(classLoaderUrls);
				Class<?> m2lPlugin = urlClassLoader.loadClass("eu.securedfp7.m2lservice.plugin.M2LPlugin");
				Constructor<?> constructor = m2lPlugin.getConstructor();
		        Object m2lPluginObj = constructor.newInstance();
		        Method method = m2lPlugin.getMethod("getConfiguration", new Class[]{String.class, String.class});
		        method.invoke(m2lPluginObj, msplFile.getAbsolutePath(), configurationFile.getAbsolutePath());
		        
		        System.out.println("Success: M2L Plugin has been invoked correctly!");
		        
			} catch (MalformedURLException | ClassNotFoundException | NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.out.println("Fail: M2L Plugin has NOT been invoked correctly!");
			}
		}
	}
}
