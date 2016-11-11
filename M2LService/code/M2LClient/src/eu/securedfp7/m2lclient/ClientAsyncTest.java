package eu.securedfp7.m2lclient;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.ws.rs.client.AsyncInvoker;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class ClientAsyncTest {

	public static void main(String[] args) {
		
		Client client = ClientBuilder.newClient();
		WebTarget target = client.target("http://localhost:8080/M2LService/rest/asynctest");
		
		final AsyncInvoker asyncInvoker = target.request().accept(MediaType.TEXT_HTML).async();
		final Future<Response> responseFuture = asyncInvoker.get();
		System.out.println("Request is being processed asynchronously.");
		try {
			final Response response = responseFuture.get();
			System.out.println("Response received : " + response);
			System.out.println("Response from GET method : " + response.readEntity(String.class));
			
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		    // get() waits for the response to be ready
		
		System.out.println("Response received.");

	}

}
