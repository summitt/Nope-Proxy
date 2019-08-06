package josh.utils;

import java.io.EOFException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.NifSelector;

import josh.utils.events.DNSEvent;
import josh.utils.events.DNSTableEventListener;
import josh.utils.events.TCPConnectionAttemptListener;
import josh.utils.events.TCPPacketEvt;
import josh.utils.events.UDPEventListener;

public class Lister implements Runnable{
	private String IP;
	private ExecutorService pool;
	private PcapHandle handle;
	private HashMap<String,String> portsFound = new HashMap<String,String>();
	
	public Lister(String IP){
		this.IP = IP;
	}

	@Override
	public void run() {
		System.out.println("Lister Started");
		try{
			InetAddress addr = InetAddress.getByName(this.IP);
		    PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
		    if (nif == null) {
		      return;
		    }
		    handle
		      = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		    handle.setFilter("tcp", BpfCompileMode.NONOPTIMIZE);
	
		    PacketListener listener
		      = new PacketListener() {
				  @Override
		          public void gotPacket(PcapPacket packet) {
		        	  TcpPacket tcp = packet.get(TcpPacket.class);
		        	  IpV4Packet ip = packet.get(IpV4Packet.class);
		        	  if(tcp.getHeader().getSyn() && !tcp.getHeader().getAck() && !ip.getHeader().getSrcAddr().toString().equals("/"+IP)){
		        		  //System.out.println(ip.getHeader().getSrcAddr() + " : " + tcp.getHeader().getDstPort().toString() );
		        		  SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd:hh:mm");
		        		  String time = sdf.format(new Date());
		        		  String key = ip.getHeader().getSrcAddr().getHostAddress() + ":"+ tcp.getHeader().getDstPort().valueAsInt();
		        		  if(portsFound.containsKey(key) && portsFound.get(key).equals(time))
		        			  return;
		        		  portsFound.put(key, time);
		        		  fireEvent(ip.getHeader().getSrcAddr().getHostAddress(),
		        				  tcp.getHeader().getDstPort().name(),
		        				  tcp.getHeader().getDstPort().valueAsInt(),
		        				  time);
		        	  }
		        	  
		          }
		        };
	
		    try {
		      pool = Executors.newCachedThreadPool();
		      handle.loop(-1, listener, pool); // This is better than handle.loop(5, listener);
		      pool.shutdown();
		    } catch (InterruptedException e) {
		      //e.printStackTrace();
		    }
	
		    handle.close();
		}catch(Exception ex){
			
		}
		System.out.println("Lister Stopped");
	  }
	public void kill(){
		try {
			handle.breakLoop();
			pool.shutdown();
			handle.close();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}
		
	}
	
	private List<TCPConnectionAttemptListener> _listeners = new ArrayList<TCPConnectionAttemptListener>();
	
	public synchronized void addEventListener(TCPConnectionAttemptListener listener)	{
		_listeners.add(listener);
	}
	public synchronized void removeEventListener(TCPConnectionAttemptListener listener)	{
		_listeners.remove(listener);
	}
	
	private void fireEvent(String sip, String service, int dport, String time){
		TCPPacketEvt event = new TCPPacketEvt(this, sip, service, dport, time);
		Iterator<TCPConnectionAttemptListener> i = _listeners.iterator();
		while(i.hasNext())	{
			i.next().TcpConnAttempt(event);
		}
	}

		
		
	
	public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
		AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
            	Lister lister = new Lister("192.168.1.129");
        		Thread t = new Thread(lister);
        		t.start();
        		
        		try {
					Thread.sleep(10*1000);

					lister.kill();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
        		
    
        		return null;
               
            }
        });
		
	  }
	

}
