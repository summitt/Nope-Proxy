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

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import josh.utils.events.ConnectionAttemptListener;
import josh.utils.events.PortConnectEvt;

public class Lister implements Runnable {
	private String IP;
	private ExecutorService pool;
	private PcapHandle handle;
	private HashMap<String, String> portsFound = new HashMap<String, String>();

	public Lister(String IP) {
		this.IP = IP;
	}

	@Override
	public void run() {
		System.out.println("Lister Started");
		try {
			InetAddress addr = InetAddress.getByName(this.IP);
			System.out.println("#### LIST OF DEVS ####");

			List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

			for (PcapNetworkInterface device : devices) {
				System.out.println(device.getName());
			}
			System.out.println("###############");
			System.out.println(addr);
			PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

			if (nif == null) {
				System.out.println("No Interface Matches IP");
				return;
			}
			handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
			System.out.println("(tcp or udp) and not dns and ip.dst == " + this.IP);
			handle.setFilter("(tcp or udp) and !port 53 and dst net " + this.IP, BpfCompileMode.OPTIMIZE);

			PacketListener listener = new PacketListener() {
				@Override
				public void gotPacket(Packet packet) {
					TcpPacket tcp = packet.get(TcpPacket.class);
					UdpPacket udp = packet.get(UdpPacket.class);
					IpV4Packet ip = packet.get(IpV4Packet.class);

					if ((udp == null && tcp == null) || ip == null)
						return;

					SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm");
					String time = sdf.format(new Date());
					String key = ip.getHeader().getSrcAddr().getHostAddress() + ":";
					String proto = "TCP";
					String service = "";
					int destPort=-1;

					if (tcp != null && tcp.getHeader().getSyn() && !tcp.getHeader().getAck()) {
						key += tcp.getHeader().getDstPort().valueAsInt() + ":" + proto;
						service = tcp.getHeader().getDstPort().name();
						destPort = tcp.getHeader().getDstPort().valueAsInt();
					}
					else if (udp != null) {
						proto= "UDP";
						key += udp.getHeader().getDstPort().valueAsInt() + ":" + proto;
						service = udp.getHeader().getDstPort().name();
						destPort = udp.getHeader().getDstPort().valueAsInt();
					}

					if ((portsFound.containsKey(key) && portsFound.get(key).equals(time)) || destPort == -1 )
						return;
					portsFound.put(key, time);
					fireEvent(ip.getHeader().getSrcAddr().getHostAddress(),
							service,
							destPort,
							time, 
							proto);

				}
			};

			try {
				pool = Executors.newCachedThreadPool();
				handle.loop(-1, listener, pool); // This is better than handle.loop(5, listener);
				pool.shutdown();
			} catch (InterruptedException e) {
				// e.printStackTrace();
			}

			handle.close();
		} catch (Exception ex) {

		}
		System.out.println("Lister Stopped");
	}

	public void kill() {
		try {
			handle.breakLoop();
			pool.shutdown();
			handle.close();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}

	}

	private List<ConnectionAttemptListener> _listeners = new ArrayList<ConnectionAttemptListener>();

	public synchronized void addEventListener(ConnectionAttemptListener listener) {
		_listeners.add(listener);
	}

	public synchronized void removeEventListener(ConnectionAttemptListener listener) {
		_listeners.remove(listener);
	}

	private void fireEvent(String sip, String service, int dport, String time, String proto) {
		PortConnectEvt event = new PortConnectEvt(this, sip, service, dport, time, proto);
		Iterator<ConnectionAttemptListener> i = _listeners.iterator();
		while (i.hasNext()) {
			i.next().ConnectAttempt(event);
		}
	}

	public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
		AccessController.doPrivileged(new PrivilegedAction() {
			public Object run() {
				Lister lister = new Lister("192.168.1.129");
				Thread t = new Thread(lister);
				t.start();

				try {
					Thread.sleep(10 * 1000);

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
