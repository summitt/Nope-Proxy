package josh.utils.events;

import java.util.EventObject;

public class DNSTableEvent extends EventObject{
	
	public DNSTableEvent(Object arg0) {
		super(arg0);
		// TODO Auto-generated constructor stub
	}
	private String Domain;
	private String ClientIP;
	private String HostName;
	
	public String getDomain() {
		return Domain;
	}
	public void setDomain(String domain) {
		Domain = domain;
	}
	public String getClientIP() {
		return ClientIP;
	}
	public void setClientIP(String clientIP) {
		ClientIP = clientIP;
	}
	public String getHostName() {
		return HostName;
	}
	public void setHostName(String HostName) {
		this.HostName = HostName;
	}
	
	

}
