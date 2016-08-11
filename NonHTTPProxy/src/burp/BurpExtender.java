package burp;


import java.awt.Component;
import java.io.UnsupportedEncodingException;

import javax.swing.SwingUtilities;
import josh.ui.NonHttpUI;
import josh.utils.SharedBoolean;
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
		private SharedBoolean sb = new SharedBoolean();


		@Override
	    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	    {
	        mCallbacks = callbacks;
			helpers = mCallbacks.getHelpers();
			mCallbacks.setExtensionName("NoPE Proxy");
			
			
			
			
			 // create our UI
	       SwingUtilities.invokeLater(new Runnable() 
	        {

				@Override
				public void run() {
						
						
					 	dnsConfig = new NonHttpUI(mCallbacks, helpers, sb);

						if(dnsConfig.DNSIP != null &&  !dnsConfig.equals("")){
							list.ADDRESS = dnsConfig.DNSIP.split("\\.");
						}
						
						list= new UDPListener(Integer.parseInt(dnsConfig.getTxtDNSPort().getText()), sb);
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
									/*if(dnsConfig.DNSIP != null && !dnsConfig.equals(""))
										list.ADDRESS = dnsConfig.DNSIP.split("\\.");
									list.setPort(Integer.parseInt(dnsConfig.getTxtDNSPort().getText()));*/
									if(e.getAddress()!= null && !e.getAddress().equals(""))
										list.ADDRESS = e.getAddress().split("\\.");
									list.setPort(e.getPort());
									
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
			
			return "NoPE Proxy";
		}



		@Override
		public Component getUiComponent() {
			
			return dnsConfig;
		}


		
	}
	
	
	
	

