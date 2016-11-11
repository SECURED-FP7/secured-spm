package eu.securedfp7.m2lpluginservice;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "M2LPluginItem")
public class M2LPluginItem {

	private String name;
	private String securityControl;
	private String path;
	
	public String getName() {
		return this.name;
	}
	
	@XmlAttribute
	public void setName(String name) {
		this.name = name;
	}
	
	public String getSecurityControl(){
		return this.securityControl;
	}
	
	@XmlElement
	public void setSecurityControl(String securityControl){
		this.securityControl = securityControl;
	}
	
	public String getPath(){
		return this.path;
	}
	
	@XmlElement
	public void setPath(String path){
		this.path = path;
	}
	
}
