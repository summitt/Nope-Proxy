package josh.utils;

import java.awt.Checkbox;
import java.util.Vector;

import javax.swing.JCheckBox;



public class ProxyRowEntry {
	
	private int SvrPort;
	private int LstPort;
	private String Address;
	public ProxyRowEntry(int svrPort, int lstPort, String address) {
		super();
		SvrPort = svrPort;
		LstPort = lstPort;
		Address = address;
	}
	
	
	public Vector<Object> getRow(){
		Vector<Object> vec = new Vector<Object>();
		vec.add(new Boolean(false));
		vec.add(this.LstPort);
		vec.add(this.Address);
		vec.add(this.SvrPort);
		vec.add(new Boolean(true));
		return vec;
		
	}


	public int getSvrPort() {
		return SvrPort;
	}


	public void setSvrPort(int svrPort) {
		SvrPort = svrPort;
	}


	public int getLstPort() {
		return LstPort;
	}


	public void setLstPort(int lstPort) {
		LstPort = lstPort;
	}


	public String getAddress() {
		return Address;
	}


	public void setAddress(String address) {
		Address = address;
	}
	
	
	



}
