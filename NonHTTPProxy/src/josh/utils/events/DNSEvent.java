package josh.utils.events;

import java.util.EventObject;

public class DNSEvent extends EventObject  {
	
	private int port;

	public DNSEvent(Object arg0) {
		super(arg0);
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}
	

}
