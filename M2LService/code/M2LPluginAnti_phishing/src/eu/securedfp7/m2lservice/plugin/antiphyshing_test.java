package eu.securedfp7.m2lservice.plugin;

public class antiphyshing_test {

	public static void main(String[] args) {
		
		M2LPlugin antiphishingPlugin = new M2LPlugin();
		antiphishingPlugin.getConfiguration("mspl_test.base64", "test.conf.base64");
		//squidPlugin.getConfiguration("ICT_mspl_father.xml.base64", "ICT_squid_father.conf.base64");
		//squidPlugin.getConfiguration("ICT_mspl_father.xml", "ICT_squid_father.conf");
		//squidPlugin.getConfiguration("ICT_mspl_son.xml.base64", "ICT_squid_son.conf.base64");
		//squidPlugin.getConfiguration("ICT_mspl_son.xml", "ICT_squid_son.conf");
		

	}

}
