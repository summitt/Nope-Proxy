package burp;

//public class BurpExtender {
	/*
	 * Note - you need to rename this file to BurpExtender.java before compiling it
	 */


import java.awt.Component;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.swing.SwingUtilities;
import josh.ui.NonHttpUI;
import josh.utils.events.DNSConfigListener;
import josh.utils.events.DNSEvent;
import josh.utils.events.UDPEventListener;
import josh.dnsspoof.UDPListener;
import burp.*;






	public class BurpExtender implements IBurpExtender, ITab
	{
	    private NonHttpUI dnsConfig; 
		private UDPListener list; 
		public IBurpExtenderCallbacks mCallbacks;
		private IExtensionHelpers helpers;
		private Thread ListThread = null;


		@Override
	    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	    {
	        mCallbacks = callbacks;
			helpers = mCallbacks.getHelpers();
			mCallbacks.setExtensionName("NonHTTPMiTM");
			
			
			
			
			 // create our UI
	       SwingUtilities.invokeLater(new Runnable() 
	        {

				@Override
				public void run() {
						
						
					 	dnsConfig = new NonHttpUI(mCallbacks, helpers);

						if(dnsConfig.DNSIP != null &&  !dnsConfig.equals("")){
							list.ADDRESS = dnsConfig.DNSIP.split("\\.");
						}
						
						list= new UDPListener(Integer.parseInt(dnsConfig.getTxtDNSPort().getText()));
						list.Callbacks = mCallbacks;
					
						list.addEventListener(new UDPEventListener(){

							@Override
							public void UDPDown(DNSEvent e) {
								
								mCallbacks.issueAlert("DNSMiTM: DNS Server Stopped.");
								dnsConfig.DNSStopped();
							}
							
						});
						
						list.addTableEventListener( dnsConfig);
						
						
						dnsConfig.addEventListener( new DNSConfigListener(){

							@Override
							public void DNSToggle(DNSEvent e) {
								if(!dnsConfig.isDNSRunning){
									mCallbacks.printOutput("Starting DNS Server");
									if(dnsConfig.DNSIP != null && !dnsConfig.equals(""))
										list.ADDRESS = dnsConfig.DNSIP.split("\\.");
									list.setPort(Integer.parseInt(dnsConfig.getTxtDNSPort().getText()));
									ListThread = new Thread(list);
									ListThread.start();
							        mCallbacks.issueAlert("DNSMiTM: DNS Server Started.");
								}else{
									ListThread.interrupt();
									list.StopServer();
									mCallbacks.issueAlert("DNSMiTM: DNS is Shutting Down");
								}
							}
								
						});
						

				        

				        
				        if(dnsConfig.getAutoStart()){
				        	ListThread = new Thread(list);
				        	ListThread.start();
					        mCallbacks.issueAlert("DNSMiTM: DNS Server Started.");
						}
						mCallbacks.customizeUiComponent(dnsConfig);
		                mCallbacks.addSuiteTab(BurpExtender.this);
		                
		                
					
				}
	        
	        });
			
			
	       
	    }
	    

	  

		@Override
		public String getTabCaption() {
			
			return "NonHTTPMiTM ( ⧉ ⦣ ⧉ )";
		}



		@Override
		public Component getUiComponent() {
			
			return dnsConfig;
		}


		
	}
	
	
	
	

