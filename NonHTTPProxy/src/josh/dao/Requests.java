package josh.dao;

import java.util.Base64;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;


@Entity
@Table(name = "requests")
public class Requests {
	 @Id
	 @Column(name = "id")
	 @GeneratedValue
	private int id;
	 @Column(name = "alt_id")
	private int alt_id; 
	 @Column(name = "data")
	private String data;
	 @Column(name = "original")
	private String original;
	 @Column(name = "srcip")
	private String srcIp;
	 @Column(name = "dstip")
	private String dstIp;
	 @Column(name = "bytes")
	private int bytes;
	 @Column(name = "srcport")
	private int srcPort;
	 @Column(name = "dstport")
	private int dstPort;
	 @Column(name = "date")
	private Long date;
	 @Column(name = "direction")
	private String direction;
	 @Column(name = "data_str")
	private String data_str;
	 @Column(name = "original_str")
	private String original_str;
	
	 
    public Requests(){};
	 
	public Requests(int Index, byte[] requestResponse, byte[] original, String SrcIp,int SrcPort, String DstIP, int DstPort, String Direction, Long time, int bytes){
		this.alt_id = Index;
		this.data = Base64.getEncoder().encodeToString(requestResponse);
		this.original =  Base64.getEncoder().encodeToString(original);
		this.srcIp = SrcIp;
		this.srcPort =  SrcPort;
		this.dstIp = DstIP;
		this.dstPort =  DstPort;
		this.direction = Direction;
		this.date = time;
		this.bytes = bytes;
		this.original_str = new String(original).replaceAll("[^a-zA-Z0-9~!@#$%^&*()_+`\\-=,./<>?\\s]", "");
		this.data_str = new String(requestResponse).replaceAll("[^a-zA-Z0-9~!@#$%^&*()_+`\\-=,./<>?\\s]", "");
		
		
	}

	public int getId() {
		return id;
	}

	public int getAlt_id() {
		return alt_id;
	}

	public byte[] getData() {
		
		return Base64.getDecoder().decode(data);
		
	}

	public byte[] getOriginal() {
		return Base64.getDecoder().decode(original);
	}

	public String getSrcIp() {
		return srcIp;
	}

	public String getDstIp() {
		return dstIp;
	}

	public int getBytes() {
		return bytes;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public Long getDate() {
		return date;
	}

	public String getDirection() {
		return direction;
	}

	public void setId(int id) {
		this.id = id;
	}

	public void setAlt_id(int alt_id) {
		this.alt_id = alt_id;
	}

	public void setData(String data) {
		this.data = data;
	}

	public void setOriginal(String original) {
		this.original = original;
	}

	public void setSrcIp(String srcIp) {
		this.srcIp = srcIp;
	}

	public void setDstIp(String dstIp) {
		this.dstIp = dstIp;
	}

	public void setBytes(int bytes) {
		this.bytes = bytes;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public void setDate(Long date) {
		this.date = date;
	}

	public void setDirection(String direction) {
		this.direction = direction;
	}

	public String getData_str() {
		return data_str;
	}

	public void setData_str(String data_str) {
		this.data_str = data_str;
	}

	public String getOriginal_str() {
		return original_str;
	}

	public void setOriginal_str(String original_str) {
		this.original_str = original_str;
	}
	
	
	
	
	
	
	
	
}
