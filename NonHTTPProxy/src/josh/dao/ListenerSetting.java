package josh.dao;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "ListenerSetting")
public class ListenerSetting {
	
	 @Id
	 @Column(name = "id")
	 @GeneratedValue
	private int id;
	 @Column(name = "lport")
	private int lport;
	 @Column(name = "sport")
	private int sport;
	 @Column(name = "sip")
	private String sip;
	 @Column(name = "cert")
	private String cert;
	 @Column(name = "ssl")
	private boolean ssl;
	 
	public ListenerSetting(){}
	 
	public ListenerSetting(int lport, int sport, String sip, String cert, boolean ssl){
		this.lport = lport;
		this.sport = sport;
		this.sip = sip;
		this.cert = cert;
		this.ssl = ssl;
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public int getLport() {
		return lport;
	}
	public void setLport(int lport) {
		this.lport = lport;
	}
	public int getSport() {
		return sport;
	}
	public void setSport(int sport) {
		this.sport = sport;
	}
	public String getSip() {
		return sip;
	}
	public void setSip(String sip) {
		this.sip = sip;
	}
	public String getCert() {
		return cert;
	}
	public void setCert(String cert) {
		this.cert = cert;
	}
	public boolean isSsl() {
		return ssl;
	}
	public void setSsl(boolean ssl) {
		this.ssl = ssl;
	}
	

}
