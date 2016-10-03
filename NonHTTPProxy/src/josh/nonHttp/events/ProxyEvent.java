package josh.nonHttp.events;

import java.util.EventObject;

import josh.nonHttp.GenericMiTMServer;
import josh.nonHttp.GenericUDPMiTMServer;

@SuppressWarnings("serial")
public class ProxyEvent extends EventObject {
	private byte[] Data;
	private byte[] OriginalData;
	private String Direction;
	private int SrcPort;
	private int DstPort;
	private String SrcIP;
	private String DstIP;
	private Object mtm;
	private GenericUDPMiTMServer mtmUDP;

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


	public Object getMtm() {
		return mtm;
	}
	public boolean isTCPMtm(){
		if(this.mtm.getClass().getName().contains("UDP"))
			return false;
		else 
			return true;
	}
	
	public GenericUDPMiTMServer getUDPMtm(){
		return (GenericUDPMiTMServer)this.mtm;
	}
	public GenericMiTMServer getTCPMtm(){
		return (GenericMiTMServer)this.mtm;
	}

	public void setMtm(Object mtm) {
		this.mtm = mtm;
	}
	/*public GenericUDPMiTMServer getUDPMtm() {
		return mtmUDP;
	}

	public void setUDPMtm(GenericUDPMiTMServer mtm) {
		this.mtmUDP = mtm;
	}*/

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

	public byte[] getOriginalData() {
		return OriginalData;
	}

	public void setOriginalData(byte[] originalData) {
		OriginalData = originalData;
	}
	
	
	
	
	
	
	

}
