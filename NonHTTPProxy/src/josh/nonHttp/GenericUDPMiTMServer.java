package josh.nonHttp;
//

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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
	private int interceptType = 0; // 0=both, 1=c2s, 2=s2c
	public InterceptData interceptc2s;
	public InterceptData intercepts2c;
	private DatagramSocket udpServerSocket = null;
	Socket udpConnectionSock;
	Socket udpClientSock;
	Vector<Thread> threads = new Vector<Thread>();
	Vector<SendUDPData> sends = new Vector<SendUDPData>();
	HashMap<SendUDPData, SendUDPData> pairs = new HashMap<SendUDPData, SendUDPData>();
	HashMap<Integer, Thread> treads2 = new HashMap<Integer, Thread>();
	boolean isRunning = false;
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

	public void setPythonMange(boolean mangle) {
		this.MangleWithPython = mangle;
	}

	public void KillThreads() {

		// System.out.println("Number of Data buffer threads is: " + threads.size());
		for (int i = 0; i < threads.size(); i++) {
			// System.out.println("Interrrpting Thread");
			try {
				((Socket) sends.get(i).sock).shutdownInput();
				((Socket) sends.get(i).sock).shutdownOutput();
				((Socket) sends.get(i).sock).close();
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
			}
			sends.get(i).killme = true;
			threads.get(i).interrupt();

		}

		try {
			udpServerSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Override
	public void run() {
		Callbacks.printOutput("Starting UDP New Server.");
		this.isRunning = true;
		if (this.ServerAddress == null || this.ServerPort == 0 | this.ListenPort == 0) {
			Callbacks.printOutput("Ports and or Addresses are blank");
			this.isRunning = false;
			return;
		}
		try {
			udpServerSocket = new DatagramSocket(this.ListenPort);
			DatagramSocket sendToServerSocket = new DatagramSocket();

			while (true && !killme) {
				try {
					Callbacks.printOutput("New UDP MiTM Instance Created");

					//Listen for new connections
					byte[] buffer = new byte[2056];	
					DatagramPacket udpPacket = new DatagramPacket(buffer, buffer.length);
					udpServerSocket.receive(udpPacket);


					//foware this data to the real server
					DatagramPacket serverRequest =  null;
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
						InetAddress inetAddress = InetAddress.getByAddress(byteOctets);
						serverRequest = new DatagramPacket(buffer, buffer.length, inetAddress, this.ServerPort);
					}else{
						InetAddress inetAddress = InetAddress.getByName(this.ServerAddress);
						serverRequest = new DatagramPacket(buffer, buffer.length, inetAddress, this.ServerPort);
					}
					sendToServerSocket.send(serverRequest);

					// Wait for a response from the real server
					byte [] serverBuffer = new byte[2056];
					DatagramPacket serverToClientPacket = new DatagramPacket(serverBuffer, serverBuffer.length);
					sendToServerSocket.receive(serverToClientPacket);

					// Forware the sever response back to the client
					InetAddress clientAddress = udpPacket.getAddress();
					int clientPort = udpPacket.getPort();
					DatagramPacket response = new DatagramPacket(serverBuffer, serverBuffer.length, clientAddress, clientPort);
					udpServerSocket.send(response);

				} catch (ConnectException e) {
					String message = e.getMessage();
					System.out.println(e.getMessage());
					if (message.equals("Connection refused"))
						Callbacks.printOutput(
								"Error: Connection Refused to " + this.ServerAddress + ":" + this.ServerPort);
					else
						Callbacks.printOutput(e.getMessage());
					udpConnectionSock.close();
				}

			}
			sendToServerSocket.close();
			udpServerSocket.close();
		} catch (Exception ex) {
			Callbacks.printOutput(ex.getMessage());

		}
		Callbacks.printOutput("Main Thread Has Died but thats ok.");
		isRunning = false;

	}

	public boolean isRunning() {
		return this.isRunning;
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

	private void KillSocks(SendUDPData sd) {
		// System.out.println(sd.Name);
		try {
			if (sd.isSSL()) {
				/*
				 * ((SSLSocket)sd.sock).shutdownInput();
				 * ((SSLSocket)sd.sock).shutdownOutput();
				 */
				((SSLSocket) sd.sock).close();
			} else {
				/*
				 * ((Socket)sd.sock).shutdownInput();
				 * ((Socket)sd.sock).shutdownOutput();
				 */
				((Socket) sd.sock).close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {

		}
	}

	@Override
	public void Closed(SendClosedEvent e) {
		SendUDPData tmp = (SendUDPData) e.getSource();
		if (pairs.containsKey(tmp)) {
			pairs.get(tmp).killme = true;
			// pairs.remove(tmp);

		} else if (pairs.containsValue(tmp)) {
			for (SendUDPData key : pairs.keySet()) {
				if (pairs.get(key).equals(tmp)) {
					key.killme = true;
					pairs.remove(key);
					KillSocks(tmp);
					KillSocks(key);
				}
			}
		}

	}

}
