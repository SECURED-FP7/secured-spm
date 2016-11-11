package eu.fp7.secured.spm.m2lservice.impl;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.m2lservice.rev150105.M2lserviceService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.m2lservice.rev150105.M2ltranslateInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.m2lservice.rev150105.M2ltranslateOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.m2lservice.rev150105.M2ltranslateOutputBuilder;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

public class M2lserviceImpl implements M2lserviceService, Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(M2lserviceImpl.class);
    private final ExecutorService executor;

    public M2lserviceImpl() {
        executor = Executors.newCachedThreadPool();
    }

    @Override
    public void close() throws IOException {
        executor.shutdown();
        while (!executor.isShutdown()) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                //e.printStackTrace();
                LOG.error(getStackTrace(e));
            }
        }
    }

    @Override
    //public Future<RpcResult<M2ltranslateOutput>> m2ltranslate(M2ltranslateInput input) {
    public ListenableFuture<RpcResult<M2ltranslateOutput>> m2ltranslate(M2ltranslateInput input){
        final SettableFuture<RpcResult<M2ltranslateOutput>> futureResult = SettableFuture.create();

        executor.submit(new M2ltranslateTask(input, futureResult));

        return futureResult;
    }

    private class M2ltranslateTask implements Callable<Void> {

        final M2ltranslateInput input;
        final SettableFuture<RpcResult<M2ltranslateOutput>> futureResult;

        public M2ltranslateTask (final M2ltranslateInput input, final SettableFuture<RpcResult<M2ltranslateOutput>> futureResult) {
            this.input = input;
            this.futureResult = futureResult;
        }

        private String translate(String mspl_input, String securityControlInput) throws IOException {
            //TBD: 'mspl_input': path to the file with the mspl policies

            // Validate the input mspl file
            File msplFile;
            try{
                msplFile = File.createTempFile("mspl_input", ".xml");
                String path_mspl = msplFile.getPath();

                //msplFile = new File(mspl_input);
                LOG.info("MSPL File at " + msplFile.getPath());
                if (msplFile.exists()) {
                    msplFile.delete();
                    LOG.info("Deleting File " + msplFile.getPath());
                    //return("Error: the provided msplFile path does not exist");
                }

                Files.write( Paths.get(path_mspl), mspl_input.getBytes(), StandardOpenOption.CREATE);

            } catch (Exception e1) {
                LOG.error(getStackTrace(e1));
                return("Error: error while verifying the input mspl file" + mspl_input);
            }

            //DOWNLOADING THE PLUGIN
            //Define a temporal plugin file
            File pluginFile =  File.createTempFile("general-plugin", ".jar");;
            //String pluginFilePath = "/tmp/general-plugin.jar";
            String pluginFilePath = pluginFile.getPath();
            try{
                // create the pluging file
                // TODO: define the actual path where this temporary files will be stored
                //pluginFile = new File(pluginFilePath);
                if(pluginFile.exists())
                {
                    pluginFile.delete();
                }
                pluginFile.createNewFile();
            } catch (Exception e1) {
                LOG.error(getStackTrace(e1));
                return("Error: error while creating the temporal pluging file" + pluginFilePath);
            }

            // Contact the PlugingService repository and download the plugin file;
            // THE PORT 8080 IS USED BY THE CONTROLLER --> TBD: THE PORT TO BE USED. For this example, we are
            // using the port 8090 in the same host where the controller is executed (localhost)
            String serviceURL = "http://localhost:8090/M2LPluginService/rest/getplugin";

            //String securityControl = "general";
            String securityControl = securityControlInput;
            LOG.info("getting plugin " + serviceURL +"/"+securityControl);

            try {
                //Define the REST Client
                Client client = ClientBuilder.newClient();

                URL website = new URL(serviceURL + "/" + securityControl);
                ReadableByteChannel rbc = Channels.newChannel(website.openStream());
                FileOutputStream fos = new FileOutputStream(pluginFile);
                fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
                fos.close();

            } catch (Exception ex) {
                LOG.error(getStackTrace(ex));
                return("Error: error while getting the pluging from " + serviceURL + "/" + securityControl);
            }

            // EXECUTE THE TRANSLATION PROCESS AND STORE THE RESULT IN A TMP FILE
            //File configurationFile = this.createDummyFile(absPath+"configurations_repository/"+securityControl+".conf.dat");
            //File configurationFile = new File("/tmp/"+securityControl+".conf.dat");

            File configurationFile = File.createTempFile(securityControl+".conf",".dat");

            if(configurationFile.exists())
            {
                configurationFile.delete();
            }

            try {
                URL[] classLoaderUrls = new URL[]{new URL("file://" + pluginFile.getAbsolutePath())};
                URLClassLoader urlClassLoader = new URLClassLoader(classLoaderUrls);
                Class<?> m2lPlugin = urlClassLoader.loadClass("eu.securedfp7.m2lservice.plugin.M2LPlugin");
                Constructor<?> constructor = m2lPlugin.getConstructor();
                Object m2lPluginObj = constructor.newInstance();
                Method method = m2lPlugin.getMethod("getConfiguration", new Class[]{String.class, String.class});
                method.invoke(m2lPluginObj, msplFile.getAbsolutePath(), configurationFile.getAbsolutePath());
                urlClassLoader.close();
            } catch (MalformedURLException | ClassNotFoundException | NoSuchMethodException | SecurityException
                    | InstantiationException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException e) {
                // TODO Auto-generated catch block
                //e.printStackTrace();
                LOG.error(getStackTrace(e));
                return("Error: error while execution the translation process " + pluginFile.getAbsolutePath());
            }

            //return configurationFile.getAbsolutePath();
            LOG.info("ConfigurationFile at: " + configurationFile.getAbsolutePath());
            return readFile(configurationFile.getPath(), Charset.defaultCharset());
        }

        @Override
        public Void call() {

            M2ltranslateOutputBuilder output = new M2ltranslateOutputBuilder();
            RpcResultBuilder<M2ltranslateOutput> rpcResult;

            try {
                String mspl_rules_file =  input.getMsplRules();
                String security_control = input.getSecurityControl();
                String result = this.translate(mspl_rules_file, security_control);

                output.setPsaConfig(result);

            } catch (Exception e) {
                /* Return error result. */
                output.setPsaConfig("Unexpected ERROR!! [withing the thread]");
            }
            rpcResult = RpcResultBuilder.<M2ltranslateOutput>success(output.build());

            futureResult.set(rpcResult.build());

            return null;
        }
    }

    public String getStackTrace(Throwable aThrowable) {
        Writer result = new StringWriter();
        PrintWriter printWriter = new PrintWriter(result);
        aThrowable.printStackTrace(printWriter);
        return result.toString();
    }

    public static  String readFile(String path, Charset encoding) throws IOException{
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }
}
