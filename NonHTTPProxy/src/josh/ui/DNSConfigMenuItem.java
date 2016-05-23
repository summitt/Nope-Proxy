package josh.ui;

import java.awt.EventQueue;

import burp.IHttpRequestResponse;
import burp.IMenuItemHandler;

public class DNSConfigMenuItem implements IMenuItemHandler{
	private NonHttpUI config;
	
	public DNSConfigMenuItem(NonHttpUI config){
		this.config = config;
	}

	@Override
	public void menuItemClicked(String arg0, IHttpRequestResponse[] arg1) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					config.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		
	}

}
