package eu.securedfp7.m2lservice.plugin;

public class antiphyshing_test_upc {

	public static void main(String[] args) {

		M2LPlugin antiphyshingPlugin = new M2LPlugin();
		antiphyshingPlugin.getConfiguration("/home/rserral/SECURED/M2L/spm/M2LService/code/M2LClient/testfiles/mspl_squid_daughter.xml", "/tmp/mspl_squid_daughter.conf");
	}

}
