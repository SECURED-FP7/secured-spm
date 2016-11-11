package eu.securedfp7.m2lservice.plugin;

public class antiphyshing_test_upc {

	public static void main(String[] args) {

		M2LPlugin antiphyshingPlugin = new M2LPlugin();
		antiphyshingPlugin.getConfiguration("mspl_squid_daughter.xml", "mspl_squid_daughter.conf");
	}

}
