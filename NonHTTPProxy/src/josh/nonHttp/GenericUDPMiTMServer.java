package josh.nonHttp;
//

import java.io.IOException;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IBurpExtenderCallbacks;
import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.ui.utils.InterceptData;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;
import josh.utils.events.SendClosedEvent;
import josh.utils.events.SendClosedEventListener;

public class GenericUDPMiTMServer
		implements Runnable, ProxyEventListener, PythonOutputEventListener, SendClosedEventListener {

	public int ListenPort;
	public int ServerPort;
	public String ServerAddress;
	public String ServerHostandIP;
	private boolean killme = false;
	protected boolean isInterceptOn = false;
	public InterceptData interceptc2s;
	public InterceptData intercepts2c;
	public DatagramSocket udpServerSocket = null;
	public final int INTERCEPT_C2S = 1;
	public final int INTERCEPT_S2C = 2;
	public final int INTERCEPT_BOTH = 0;
	private int IntercetpDirection = 0;
	private IBurpExtenderCallbacks Callbacks;
	private boolean MangleWithPython = false;

	public GenericUDPMiTMServer(boolean isSSL, IBurpExtenderCallbacks Callbacks) {
		this.interceptc2s = new InterceptData(null);
		this.intercepts2c = new InterceptData(null);
		this.Callbacks = Callbacks;
	}

	public static boolean available(int port) {
		if (port < 1 || port > 65535) {
			return false;
		}

		DatagramSocket udpSocket = null;
		try {
			udpSocket = new DatagramSocket(port);
			udpSocket.setReuseAddress(true);
			return true;
		} catch (IOException e) {
		} finally {
			if (udpSocket != null) {
				udpSocket.close();
			}
		}
		System.out.println("Port " + port + " is in use.");
		return false;
	}

	private List _listeners = new ArrayList();
	private List _pylisteners = new ArrayList();

	public synchronized void addEventListener(ProxyEventListener listener) {
		_listeners.add(listener);
	}

	public synchronized void removeEventListener(ProxyEventListener listener) {
		_listeners.remove(listener);
	}

	public synchronized void addPyEventListener(PythonOutputEventListener listener) {
		_pylisteners.add(listener);
	}

	public synchronized void removePyEventListener(PythonOutputEventListener listener) {
		_pylisteners.remove(listener);
	}

	private synchronized void NewDataEvent(ProxyEvent e) {
		System.out.println(e);
		ProxyEvent event = e;
		Iterator i = _listeners.iterator();
		while (i.hasNext()) {
			((ProxyEventListener) i.next()).DataReceived(event);
		}
	}

	public synchronized void SendPyOutput(PythonOutputEvent event) {
		Iterator i = _pylisteners.iterator();
		while (i.hasNext()) {
			((PythonOutputEventListener) i.next()).PythonMessages(event);
		}
	}

	private synchronized void InterceptedEvent(ProxyEvent e, boolean isC2S) {
		ProxyEvent event = e;
		event.setMtm(this);
		Iterator i = _listeners.iterator();
		while (i.hasNext()) {
			((ProxyEventListener) i.next()).Intercepted(event, isC2S);
		}

	}

	public boolean isPythonOn() {
		return this.MangleWithPython;
	}

	public void setPythonMangle(boolean mangle) {
		this.MangleWithPython = mangle;
	}

	@Override
	public void run() {
		Callbacks.printOutput("Starting UDP New Server.");
		if (this.ServerAddress == null || this.ServerPort == 0 | this.ListenPort == 0) {
			Callbacks.printOutput("Ports and or Addresses are blank");
			return;
		}
		try {
			udpServerSocket = new DatagramSocket(this.ListenPort);
			DatagramSocket sendToServerSocket = new DatagramSocket();
			InetAddress serverAddress = null;
			String IPV4_PATTERN = "^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.(?!$)|$)){4}$";
			Pattern pattern = Pattern.compile(IPV4_PATTERN);
			Matcher matcher = pattern.matcher(this.ServerAddress);
			if(matcher.matches()){
				String [] stringOctets = this.ServerAddress.split("\\.");
				byte [] byteOctets = new byte[4];
				byteOctets[0] = (byte) (Integer.parseInt(stringOctets[0]) & 0xFF);
				byteOctets[1] = (byte) (Integer.parseInt(stringOctets[1]) & 0xFF);
				byteOctets[2] = (byte) (Integer.parseInt(stringOctets[2]) & 0xFF);
				byteOctets[3] = (byte) (Integer.parseInt(stringOctets[3]) & 0xFF);
				serverAddress = InetAddress.getByAddress(byteOctets);
			}else{
				serverAddress = InetAddress.getByName(this.ServerAddress);
			}
			//This information will be populated on the firest request
			InetAddress clientAddress = null;
			int clientPort = -1;

			while (true && !killme) {
				try {
					byte[] buffer = new byte[2056];	
					DatagramPacket udpPacket = new DatagramPacket(buffer, buffer.length);
					udpServerSocket.receive(udpPacket);

					if(udpPacket.getPort() != this.ServerPort){
						clientAddress = udpPacket.getAddress();
						clientPort = udpPacket.getPort();

						UDPDataPipeline pipeline = new UDPDataPipeline(this,buffer,clientAddress,clientPort, serverAddress, ServerPort, true);
						pipeline.addEventListener(GenericUDPMiTMServer.this);
						pipeline.addPyEventListener(this);
						pipeline.addSendClosedEventListener(this);
						Thread c2s = new Thread(pipeline);
						c2s.run();
					}else if(clientPort == -1){
						System.out.println("Don't have a client port yet");
					}else{
						UDPDataPipeline pipeline = new UDPDataPipeline(this,buffer,serverAddress,ServerPort, clientAddress, clientPort, false);
						pipeline.addEventListener(GenericUDPMiTMServer.this);
						pipeline.addPyEventListener(this);
						pipeline.addSendClosedEventListener(this);
						Thread s2c = new Thread(pipeline);
						s2c.run();
					}

				} catch (ConnectException e) {
					String message = e.getMessage();
					System.out.println(e.getMessage());
					if (message.equals("Connection refused"))
						Callbacks.printOutput(
								"Error: Connection Refused to " + this.ServerAddress + ":" + this.ServerPort);
					else
						Callbacks.printOutput(e.getMessage());
				}

			}
			sendToServerSocket.close();
			udpServerSocket.close();
		} catch (Exception ex) {
			Callbacks.printOutput(ex.getMessage());

		}
		Callbacks.printOutput("Main Thread Has Died but thats ok.");
	}

	public void setIntercept(boolean set) {
		this.isInterceptOn = set;
	}

	public boolean isInterceptOn() {
		return this.isInterceptOn;
	}

	public void setInterceptDir(int direction) {
		this.IntercetpDirection = direction;
	}

	public int getIntercetpDir() {
		return this.IntercetpDirection;
	}

	public void forwardC2SRequest(byte[] bytes) {
		// System.out.println("Forwarding Request...");
		interceptc2s.setData(bytes);
	}

	public void forwardS2CRequest(byte[] bytes) {
		// System.out.println("Forwarding Request...");
		intercepts2c.setData(bytes);
	}

	@Override
	public void DataReceived(ProxyEvent e) {
		NewDataEvent(e);

	}

	@Override
	public void Intercepted(ProxyEvent e, boolean isC2S) {
		InterceptedEvent(e, isC2S);

	}

	@Override
	public void PythonMessages(PythonOutputEvent e) {
		SendPyOutput(e);

	}

	public void KillThreads(){
		System.out.println("kill upd threads");
		this.udpServerSocket.close();
		this.killme = true;
	}

	@Override
	public void Closed(SendClosedEvent e) {
		this.killme = true;
	}

}
