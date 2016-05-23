package josh.nonHttp.events;

import java.util.EventObject;

import josh.nonHttp.GenericMiTMServer;

@SuppressWarnings("serial")
public class ProxyEvent extends EventObject {
	private byte[] Data;
	private String Direction;
	private int SrcPort;
	private int DstPort;
	private String SrcIP;
	private String DstIP;
	private GenericMiTMServer mtm;

	public ProxyEvent(Object arg0) {
		super(arg0);
	}
	
	public byte[] getData(){
		return Data;
	}
	
	public void setData(byte [] Data){
		this.Data=Data;
	}
	public void setData(String Data){
		this.Data=Data.getBytes();
	}
	public String getDataAsString(){
		String str = "";
		for(int i=0; i< Data.length; i++){
			str+=(char)Data[i];
		}
		return str;
	}

	public String getDirection() {
		return Direction;
	}

	public void setDirection(String direction) {
		Direction = direction;
	}


	public GenericMiTMServer getMtm() {
		return mtm;
	}

	public void setMtm(GenericMiTMServer mtm) {
		this.mtm = mtm;
	}

	public int getSrcPort() {
		return SrcPort;
	}

	public void setSrcPort(int srcPort) {
		SrcPort = srcPort;
	}

	public int getDstPort() {
		return DstPort;
	}

	public void setDstPort(int dstPort) {
		DstPort = dstPort;
	}

	public String getSrcIP() {
		return SrcIP;
	}

	public void setSrcIP(String srcIP) {
		SrcIP = srcIP;
	}

	public String getDstIP() {
		return DstIP;
	}

	public void setDstIP(String dstIP) {
		DstIP = dstIP;
	}
	
	
	
	
	
	

}
