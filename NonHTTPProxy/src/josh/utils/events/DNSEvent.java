package josh.utils.events;

import java.util.EventObject;

public class DNSEvent extends EventObject  {
	
	private int port;
	private String address;

	public DNSEvent(Object arg0) {
		super(arg0);
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}
	
	

}
