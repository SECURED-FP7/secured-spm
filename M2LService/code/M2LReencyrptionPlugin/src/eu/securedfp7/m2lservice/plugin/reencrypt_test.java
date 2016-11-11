package eu.securedfp7.m2lservice.plugin;

public class reencrypt_test{
  public static void main(String[] args) {
  

  M2LPlugin reencryptPlugin = new M2LPlugin();
  reencryptPlugin.getConfiguration("MSPL_best_effort.xml", "Conf_best_effort.conf");
  reencryptPlugin.getConfiguration("MSPL_best_effort.xml.base64", "Conf_best_effort.conf.base64");
  reencryptPlugin.getConfiguration("MSPL_only_secure.xml", "Conf_only_secure.conf");
  reencryptPlugin.getConfiguration("MSPL_only_secure.xml.base64", "Conf_only_secure.conf.base64");
  reencryptPlugin.getConfiguration("MSPL_c418d3b3-8c81-4f40-8653-aa5077c7e35f.xml", "MSPL_c418d3b3-8c81-4f40-8653-aa5077c7e35f.conf");
 } 
  
}