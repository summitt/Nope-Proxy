package burp;


import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIDefaults;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.plaf.FontUIResource;

import josh.ui.NonHttpUI;
import josh.utils.SharedBoolean;
import josh.utils.events.DNSConfigListener;
import josh.utils.events.DNSEvent;
import josh.utils.events.UDPEventListener;
import josh.dnsspoof.UDPListener;
import burp.*;






	public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory
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
			mCallbacks.registerContextMenuFactory(this);
			
			
			
			
			
			
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

		
		private boolean shouldShow(){
			if(dnsConfig.ntbm.requestViewer.getComponent().isShowing() ||
				dnsConfig.ntbm.originalViewer.getComponent().isShowing() ||
				dnsConfig.intbm.requestViewer.getComponent().isShowing()){
				return true;
			}else{
				return false;
			}
		}

		@Override
		public List<JMenuItem> createMenuItems(IContextMenuInvocation inv) {
			List<JMenuItem> nopes = new ArrayList<JMenuItem>();
			if(shouldShow()){
				JMenuItem send2repeater = new JMenuItem("Send to NoPE Repeater");
				send2repeater.addActionListener(new ActionListener(){
					@Override
					public void actionPerformed(ActionEvent arg0) {
						byte [] message;
						if(dnsConfig.ntbm.requestViewer.getComponent().isShowing())
							message= dnsConfig.ntbm.requestViewer.getMessage();
						else if(dnsConfig.ntbm.originalViewer.getComponent().isShowing())
							message= dnsConfig.ntbm.originalViewer.getMessage();
						else if(dnsConfig.intbm.requestViewer.getComponent().isShowing())
							message= dnsConfig.intbm.requestViewer.getMessage();
						else
							return;
						
						dnsConfig.repeater.setMessage(message, true);
						
						
					}
					
				});
				nopes.add(send2repeater);
			}
			return nopes;
		}


		
	}
	
	
	
	

