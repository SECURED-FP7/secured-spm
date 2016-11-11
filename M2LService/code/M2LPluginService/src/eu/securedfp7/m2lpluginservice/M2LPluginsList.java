package eu.securedfp7.m2lpluginservice;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "M2LPluginsList")
public class M2LPluginsList {

	@XmlElement
    private List<M2LPluginItem> pluginsList = new ArrayList<M2LPluginItem>();
	
	public List<M2LPluginItem> getPlugins() {
        return pluginsList;
    }
 
    public void setPlugins(List<M2LPluginItem> pluginsList) {
        this.pluginsList = pluginsList;
    }   
    
    public void addPlugin(M2LPluginItem newPlugin){
    	this.pluginsList.add(newPlugin);
    }
}
