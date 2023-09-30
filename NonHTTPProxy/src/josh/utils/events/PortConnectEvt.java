package josh.utils.events;

import java.util.EventObject;

public class PortConnectEvt extends EventObject  {
	
	private String sip;
	private int dport;
	private String Service;
	private String time;
	private String Proto;

	public PortConnectEvt(Object arg0, String sip, String Service, int dport, String time, String Proto) {
		super(arg0);
		this.sip = sip;
		this.Service = Service;
		this.dport = dport;
		this.time = time;
		this.Proto = Proto;
	}

	public String getSip() {
		return sip;
	}

	public void setSip(String sip) {
		this.sip = sip;
	}

	public int getDport() {
		return dport;
	}

	public void setDport(int dport) {
		this.dport = dport;
	}

	public String getService() {
		return Service;
	}

	public void setService(String service) {
		Service = service;
	}

	public String getTime() {
		return time;
	}

	public void setTime(String time) {
		this.time = time;
	}

	public void setProto(String proto){
		this.Proto = proto;
	}
	public String getProto(){
		return this.Proto;
	}
	
	

}
