package eu.securedfp7.m2lservice.plugin;

public class antiphyshing_test {

	public static void main(String[] args) {
		
		String MSPLFileName = "ICT_mspl_father.xml.base64";
		String securityControlFileName = "ICT_squid_father.conf.base64";
		
		M2LPlugin squidPlugin = new M2LPlugin();
		squidPlugin.getConfiguration("ICT_mspl_father.xml.base64", "ICT_squid_father.conf.base64");
		squidPlugin.getConfiguration("ICT_mspl_father.xml", "ICT_squid_father.conf");
		squidPlugin.getConfiguration("ICT_mspl_son.xml.base64", "ICT_squid_son.conf.base64");
		squidPlugin.getConfiguration("ICT_mspl_son.xml", "ICT_squid_son.conf");
		

	}

}
