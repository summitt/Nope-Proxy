package josh.dnsspoof;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Header;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;

import burp.IBurpExtenderCallbacks;
import josh.utils.SharedBoolean;
import josh.utils.events.DNSEvent;
import josh.utils.events.DNSTableEvent;
import josh.utils.events.DNSTableEventListener;
import josh.utils.events.UDPEventListener;
//import jpcap.JpcapCaptor;
//import jpcap.NetworkInterface;
//import jpcap.NetworkInterfaceAddress;

public class UDPListener implements Runnable{
	private DatagramSocket datagramSocket = null;
	private boolean stop = false;
	private boolean isDown = false;
	public static String[] ADDRESS;
	private static int InterfaceNumber=0;
	private int port=5351;
	public IBurpExtenderCallbacks Callbacks; 
	private SharedBoolean sb;
	private static String ExternalDNS;
	

	private static void updateInterface(){
		String path = System.getProperty("user.home");
		
		File f = new File(path + "/.NoPEProxy/dns.properties");
		Properties config = new Properties();
		try{
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				File p = new File(path + "/.NoPEProxy/");
				
				if(!p.exists())
					p.mkdir();
				f.createNewFile();
				config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				config.store(new FileOutputStream(f), null);
			}
			
			InterfaceNumber=Integer.parseInt(config.getProperty("interface", "0"));
			ExternalDNS = config.getProperty("extDNS", "8.8.8.8");
		}catch(Exception EX){
			//Callbacks.printError(EX.getMessage());
			EX.printStackTrace();
		}
	}
	private static void updateInterface(String iface){
		String path = System.getProperty("user.home");
		File f = new File(path + "/.NoPEProxy/dns.properties");
		Properties config = new Properties();
		try{
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				File p = new File(path + "/.NoPEProxy/");
				
				if(!p.exists())
					p.mkdir();
				f.createNewFile();
				config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				config.store(new FileOutputStream(f), null);
			}
			config.setProperty("interface", iface);
			config.store(new FileOutputStream(f), null);
			//InterfaceNumber=Integer.parseInt(config.getProperty("interface", "0"));
		}catch(Exception EX){
			//Callbacks.printError(EX.getMessage());
			EX.printStackTrace();
		}
	}
	
	public UDPListener(int port, SharedBoolean sb){
		this.port = port;
		this.sb = sb;
		
		/*try 
        {
            datagramSocket = new DatagramSocket(port);
        } catch (SocketException e) { e.printStackTrace(); }  */
		
	}
	public void StopServer(){
		datagramSocket.close();
		stop = true;
	}
	public boolean isStopped(){
		return isDown;
	}

	@Override
	public void run() {

		stop = false;
		isDown = false;
		updateInterface();
		if(ADDRESS != null && !ADDRESS[0].equals("---"))
			Callbacks.printOutput("DNSMiTM: Responding IP Address is " + ADDRESS[0] + "." + ADDRESS[1] + "." +ADDRESS[2] + "." +ADDRESS[3]  );
		else{ 
			System.out.println("Could not start dns");
			this.fireEvent();
			return;
		}
		try 
        {
			Callbacks.printOutput("Using port: " + this.port);
            datagramSocket = new DatagramSocket(this.port);
           
            
        } catch (SocketException e) { 
        	Callbacks.printError(e.getMessage());
        	e.printStackTrace(); 
        } 
		
        udpWhile : while(!stop)
        {
        	byte[] buffer = new byte[1024];
        	DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            // Receive the packet.
            try {
            	//datagramSocket.setSoTimeout(1000);
                datagramSocket.receive(packet);
                new Thread( new DNSResponder(packet, datagramSocket, ADDRESS)).start();
            } catch(SocketTimeoutException ex){
            	continue udpWhile;
            }catch (IOException e) {Callbacks.printError(e.getMessage()); /*e.printStackTrace();*/ }
            
        }
        fireEvent();
        //datagramSocket.close();
	}
	public class DNSResponder implements Runnable {
		private DatagramPacket packet;
		private DatagramSocket datagramSocket; 
		private String [] ADDRESS;
		
		public DNSResponder(DatagramPacket packet, DatagramSocket datagramSocket, String [] ADDRESS){
			this.packet = packet;
			this.ADDRESS = ADDRESS;
			this.datagramSocket = datagramSocket;
		}
		
		public void run() {
			byte[] buffer = new byte[512];
            buffer = packet.getData();  
            int NN = packet.getLength();
            byte []copy = new byte [NN];
            for(int j =0; j < NN; j++){
            	copy[j] = buffer[j];
            }
            // Print the data:
            //System.out.println(new String(copy));
            String hostname = "";
            for(int k=12; k < copy.length;){
            	if(copy[k] == 0){
            		hostname = hostname.substring(0, hostname.length()-1); //removes the last period
            		break;
            	}
            	int limit = k+copy[k++] +1;
            	for(;k < limit && k < copy.length; k++)
            		hostname += "" + (char)copy[k];
            	hostname += ".";

            }
            
            String ip = packet.getAddress().getHostAddress();
            String HostName="";

        	java.net.InetAddress inetAdd;
			try {
				inetAdd = java.net.InetAddress.getByName(ip);
			
				HostName = inetAdd.getHostName();
			} catch (UnknownHostException e1) {
				Callbacks.printError(e1.getMessage());
				e1.printStackTrace();
			} 
           
            
            
            List<String>hosts=readHosts();
            Boolean override=false;
            String returnIpAddress = this.ADDRESS[0] + "." + this.ADDRESS[1] + "." +this.ADDRESS[2] + "." +this.ADDRESS[3];
            for(String line : hosts){
            	if(line.contains(hostname) && !line.startsWith("#")){
            		String hostIP = line.split(" ")[0];
            		if(hostIP.matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")){
            			returnIpAddress = hostIP;
						System.out.println("Using Host File");
						System.out.println(returnIpAddress);
        				override=true;
        				break;
            		}
            	}
            }
            
            
            if(this.ADDRESS != null && !override && sb.getDefault()){
            	returnIpAddress = this.ADDRESS[0] + "." + this.ADDRESS[1] + "." +this.ADDRESS[2] + "." +this.ADDRESS[3];
			} else if(!override) {
				try {
					DatagramPacket outdp;
					SimpleResolver resolver = new SimpleResolver(ExternalDNS);
					resolver.setTimeout(5000);
					Lookup lookup = new Lookup(hostname, Type.A);
					lookup.setResolver(resolver);
					lookup.setCache(null);
					org.xbill.DNS.Record[] records = lookup.run();
					if (lookup.getResult() == Lookup.SUCCESSFUL) {
						for (org.xbill.DNS.Record record : records) {
							returnIpAddress = record.rdataToString();
							break;
						}
					} else {
						System.out.println("DNS lookup failed.");
						String returnIP="Error Resolvng Hostname";
						fireTableEvent(hostname, ip, HostName, returnIP);
						return;
					}
				}catch(Exception e){
					System.out.println("DNS lookup failed.");
					String returnIP="Error Resolvng Hostname";
					fireTableEvent(hostname, ip, HostName, returnIP);
					return;

				}
			}
			try{
				Message request = new Message(buffer);
				Message response = new Message(request.getHeader().getID());
				Header header = response.getHeader();
				header.setFlag(Flags.QR);
				//header.setFlag(Flags.RD);
				//header.setFlag(Flags.RA);
				header.setFlag(Flags.AA);
				header.setRcode(Rcode.NOERROR);
				response.addRecord(request.getQuestion(), Section.QUESTION);
				OPTRecord optRecord = new OPTRecord(512, 0, 0);
            	response.addRecord(optRecord, Section.ADDITIONAL);
				// Add answers as needed
				response.addRecord(Record.fromString(Name.fromString(hostname+"."), Type.A, DClass.IN, 3600, returnIpAddress, Name.root), Section.ANSWER);
				byte[] resp = response.toWire();
				InetAddress addr = packet.getAddress();
				int port = packet.getPort();
				DatagramPacket outdp = new DatagramPacket(resp, resp.length, addr, port);
				datagramSocket.send(outdp);
				fireTableEvent(hostname, ip, HostName, returnIpAddress);
				return;
			}catch(Exception e){
				System.out.println(e);
				String returnIP="Error Resolvng Hostname";
				fireTableEvent(hostname, ip, HostName, returnIP);
				return;
			}
		}
		
	}
	
	private List<String> readHosts(){
		String path = System.getProperty("user.home");
		String file = path + "/.NoPEProxy/hosts.txt";
		File f = new File(file);
		/*String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "hosts.txt";
		File f = new File(file);*/
		if(!f.exists()){
			return new ArrayList<String>();
		}
		Path p = Paths.get(file);
		List<String>lines = new ArrayList<String>();
		BufferedReader reader;
		try {
			reader = Files.newBufferedReader(p);
			
			
			String line = "";
			while ((line = reader.readLine()) != null) {
				lines.add(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return new ArrayList<String>();
		}
		
		return lines;
	}
	
	// Event Stuff here
		private List<UDPEventListener> _udplisteners = new ArrayList<UDPEventListener>();
		private List<DNSTableEventListener> _dnslisteners = new ArrayList<DNSTableEventListener>();
		
		public synchronized void addEventListener(UDPEventListener listener)	{
			_udplisteners.add(listener);
		}
		public synchronized void removeEventListener(UDPEventListener listener)	{
			_udplisteners.remove(listener);
		}
		public synchronized void addTableEventListener(DNSTableEventListener listener)	{
			_dnslisteners.add(listener);
		}
		public synchronized void removeTableEventListener(DNSTableEventListener listener)	{
			_dnslisteners.remove(listener);
		}

		private synchronized void fireEvent()	{
			DNSEvent event = new DNSEvent(this);
			Iterator<UDPEventListener> i = _udplisteners.iterator();
			while(i.hasNext())	{
				i.next().UDPDown(event);
			}
		}
		
		
		
		private synchronized void fireTableEvent(String Domain, String ClientIP, String HostName, String ResponseIp)	{
			DNSTableEvent event = new DNSTableEvent(this);
			event.setClientIP(ClientIP);
			event.setDomain(Domain);
			event.setHostName(HostName);
			event.setResponseIp(ResponseIp);
			Iterator<DNSTableEventListener> i = _dnslisteners.iterator();
			while(i.hasNext())	{
				i.next().NewDomainRequest(event);
			}
		}
		public void setPort(int port){
			this.port = port;
		}
		
		

}
