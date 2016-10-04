package josh.utils;

import java.io.EOFException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.NifSelector;

public class Lister implements Runnable{
	private String IP;
	
	public Lister(String IP){
		this.IP = IP;
	}

	@Override
	public void run() {
		try{
			InetAddress addr = InetAddress.getByName(this.IP);
		    PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
		    if (nif == null) {
		      return;
		    }
		    final PcapHandle handle
		      = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		    handle.setFilter("tcp", BpfCompileMode.NONOPTIMIZE);
	
		    PacketListener listener
		      = new PacketListener() {
		          public void gotPacket(Packet packet) {
		        	  TcpPacket tcp = packet.get(TcpPacket.class);
		        	  IpV4Packet ip = packet.get(IpV4Packet.class);
		        	  if(tcp.getHeader().getSyn() && !tcp.getHeader().getAck() && !ip.getHeader().getSrcAddr().toString().equals("/"+IP)){
		        		  System.out.println(ip.getHeader().getSrcAddr() + " : " + tcp.getHeader().getDstPort().toString() );
		        	  }
		        	  
		          }
		        };
	
		    try {
		      ExecutorService pool = Executors.newCachedThreadPool();
		      handle.loop(-1, listener, pool); // This is better than handle.loop(5, listener);
		      pool.shutdown();
		    } catch (InterruptedException e) {
		      e.printStackTrace();
		    }
	
		    handle.close();
		}catch(Exception ex){
			
		}
	  }

		
		
	
	public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
		Lister lister = new Lister("192.168.1.129");
		Thread t = new Thread(lister);
		t.start();
	  }
	

}
