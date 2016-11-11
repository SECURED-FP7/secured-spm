package eu.securedfp7.m2lservice;

import java.util.concurrent.TimeUnit;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.ConnectionCallback;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.container.TimeoutHandler;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/asynctest")
public class AsyncTest {
	
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	public void asyncGetWithTimeout(@Suspended final AsyncResponse asyncResponse) {
	    asyncResponse.setTimeoutHandler(new TimeoutHandler() {
	 
	        @Override
	        public void handleTimeout(AsyncResponse asyncResponse) {
	            asyncResponse.resume(Response.status(Response.Status.SERVICE_UNAVAILABLE)
	                    .entity("Operation time out.").build());
	        }
	    });
	    asyncResponse.setTimeout(300, TimeUnit.SECONDS);
	 
	    new Thread(new Runnable() {
	 
	        @Override
	        public void run() {
	            String result = veryExpensiveOperation();
	            asyncResponse.resume(result);
	        }
	 
	        private String veryExpensiveOperation() {
	  
	        	try {
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	        	
	        	return "<html> " + "<title>" + "M2L Service - Hello" + "</title>"
	    				+ "<body><h1>" + "Hello this is M2L Service" + "</body></h1>" + "</html> ";
	        }
	    }).start();
	}
	
	
	/*
	@GET
	public void asyncGetConnectionCallback(@Suspended final AsyncResponse asyncResponse) {
		asyncResponse.register(new ConnectionCallback() {
		@Override
		public void onDisconnect(AsyncResponse asyncResponse) {
		asyncResponse.resume(Response.status(Response.Status.SERVICE_UNAVAILABLE).entity("Connection Callback").build());
		}
		});

		new Thread(new Runnable() {
		@Override
		public void run() {
		String result = veryExpensiveOperation();
		asyncResponse.resume(result);
		}

		private String veryExpensiveOperation() {
			
			try {
				Thread.sleep(60000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		return "Very Expensive Operation with Connection Callback";
		}
		}).start();
		}
		*/
}
