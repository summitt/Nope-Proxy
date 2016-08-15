package josh.nonHttp;
//

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
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

import burp.IBurpExtenderCallbacks;
import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.nonHttp.utils.InterceptData;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;
import josh.utils.events.SendClosedEvent;
import josh.utils.events.SendClosedEventListener;

public class GenericMiTMServer implements Runnable, ProxyEventListener, PythonOutputEventListener, SendClosedEventListener{
	
	
	public int ListenPort;
	public int ServerPort;
	public String ServerAddress;
	public String ServerHostandIP;
	public String CertHostName;
	private boolean killme=false;
	protected boolean isInterceptOn=false;
	private int interceptType=0; // 0=both, 1=c2s, 2=s2c
	public InterceptData interceptc2s;
	public InterceptData intercepts2c;
	Object svrSock;
	//SSLServerSocket sslSvrSock;
	Socket connectionSocket;
	Object cltSock;
	Vector<Thread> threads = new Vector<Thread>();
	Vector<SendData> sends = new Vector<SendData>();
	HashMap<SendData,SendData> pairs = new HashMap<SendData,SendData>();
	HashMap<Integer,Thread>treads2 = new HashMap<Integer,Thread>();
	boolean isSSL = false;
	boolean isRunning=false;
	public final int INTERCEPT_C2S=1;
	public final int INTERCEPT_S2C=2;
	public final int INTERCEPT_BOTH=0;
	private int IntercetpDirection=0;
	private IBurpExtenderCallbacks Callbacks;
	private boolean MangleWithPython = false;
	//SendData send;
	//SendData getD;
	
	
	
	public GenericMiTMServer(boolean isSSL, IBurpExtenderCallbacks Callbacks){
		this.interceptc2s = new InterceptData(null);
		this.intercepts2c = new InterceptData(null);
		this.isSSL = isSSL;
		this.Callbacks = Callbacks;
	}
	
	public static boolean available(int port) {
	    if (port < 1 || port > 65535) {
	        throw new IllegalArgumentException("Invalid start port: " + port);
	    }

	    ServerSocket ss = null;
	    DatagramSocket ds = null;
	    try {
	        ss = new ServerSocket(port);
	        ss.setReuseAddress(true);
	        ds = new DatagramSocket(port);
	        ds.setReuseAddress(true);
	        return true;
	    } catch (IOException e) {
	    } finally {
	        if (ds != null) {
	            ds.close();
	        }

	        if (ss != null) {
	            try {
	                ss.close();
	            } catch (IOException e) {
	                /* should not be thrown */
	            }
	        }
	    }

	    return false;
	}
	
	private List _listeners = new ArrayList();
	private List _pylisteners = new ArrayList();
	public synchronized void addEventListener(ProxyEventListener listener)	{
		_listeners.add(listener);
	}
	public synchronized void removeEventListener(ProxyEventListener listener)	{
		_listeners.remove(listener);
	}
	public synchronized void addPyEventListener(PythonOutputEventListener listener)	{
		_pylisteners.add(listener);
	}
	public synchronized void removePyEventListener(PythonOutputEventListener listener)	{
		_pylisteners.remove(listener);
	}
	private synchronized void NewDataEvent(ProxyEvent e)	{
		ProxyEvent event = e;
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			((ProxyEventListener) i.next()).DataReceived(event);
		}
	}
	
	public synchronized void SendPyOutput(PythonOutputEvent event){
		Iterator i = _pylisteners.iterator();
		while(i.hasNext())	{
			((PythonOutputEventListener) i.next()).PythonMessages(event);
		}
	}
	
	private synchronized void InterceptedEvent(ProxyEvent e, boolean isC2S)	{
		ProxyEvent event = e;
		event.setMtm(this);
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			((ProxyEventListener) i.next()).Intercepted(event, isC2S);
		}
		
	}
	public boolean isPythonOn(){
		return this.MangleWithPython;
	}
	public void setPythonMange(boolean mangle){
		this.MangleWithPython = mangle;
	}
	

	public void KillThreads(){
		
		
		//System.out.println("Number of Data buffer threads is: " + threads.size());
		for(int i=0; i<threads.size(); i++){
			//System.out.println("Interrrpting Thread");
			try {
				if(sends.get(i).isSSL()){
					((SSLSocket)sends.get(i).sock).shutdownInput();
					((SSLSocket)sends.get(i).sock).shutdownOutput();
					((SSLSocket)sends.get(i).sock).close();
				}else{
					((Socket)sends.get(i).sock).shutdownInput();
					((Socket)sends.get(i).sock).shutdownOutput();
					((Socket)sends.get(i).sock).close();
				}
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
			}
			sends.get(i).killme=true;
			threads.get(i).interrupt();
			
			
		}
		
		
		try {
			if(connectionSocket!= null)
				connectionSocket.close();
			if(isSSL)
				((SSLServerSocket)svrSock).close();
			else
				((ServerSocket)svrSock).close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e){
			e.printStackTrace();
		}
		
	}
	
    @Override
	public void run() {
    	Callbacks.printOutput("Starting New Server.");
    	this.isRunning=true;
    	if(this.ServerAddress == null || this.ServerPort == 0 | this.ListenPort == 0){
    		Callbacks.printOutput("Ports and or Addresses are blank");
    		this.isRunning=false;
    		return;
    		}
    	try{
    		if(isSSL){
    			 
    			 //testBC test = new testBC();
    			DynamicKeyStore test = new DynamicKeyStore();
    			
    		
    	         String ksPath = test.generateKeyStore("changeit",  this.CertHostName);
    	         
    	         KeyStore ks = KeyStore.getInstance("PKCS12");
    	         ks.load(new FileInputStream(ksPath), "changeit".toCharArray());
    	         
    	         KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

    	        
    	         kmf.init(ks,"changeit".toCharArray());
    	         
    	         
    	         X509Certificate[] result = new X509Certificate[ks.getCertificateChain(ks.aliases().nextElement()).length];
    	         //System.out.println(result.length);
    	         
    	         SSLContext sc = SSLContext.getInstance("TLS");
    	         sc.init(kmf.getKeyManagers(), null, null);
    	         SSLServerSocketFactory ssf = sc.getServerSocketFactory();
    	         svrSock = (SSLServerSocket) ssf.createServerSocket(this.ListenPort);
    			
    		}else
    			svrSock = new ServerSocket(this.ListenPort);
    		
    		
    		
	        while(true && !killme){
	        	try{
	        		Callbacks.printOutput("New MiTM Instance Created");
		        	//System.out.println("Number of Threads is: " + threads.size());
		        	if(isSSL)
		        		connectionSocket = ((SSLServerSocket)svrSock).accept();
		        	else
		        		connectionSocket = ((ServerSocket)svrSock).accept();
		        	
		        	
		        	
			        connectionSocket.setSoTimeout(200);
			        connectionSocket.setReceiveBufferSize(2056);
			        connectionSocket.setSendBufferSize(2056);
			        connectionSocket.setKeepAlive(false);
			        
			    	InputStream inFromClient = connectionSocket.getInputStream();
			        DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
			        
			        //Object cltSock;
			        if(isSSL){
			        	SSLSocketFactory  ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
			        	cltSock = (SSLSocket) ssf.createSocket(this.ServerAddress, this.ServerPort);
			        	((SSLSocket)cltSock).setSoTimeout(200);
			        	((SSLSocket)cltSock).setReceiveBufferSize(2056);
			        	((SSLSocket)cltSock).setSendBufferSize(2056);
			        	((SSLSocket)cltSock).setKeepAlive(false);
			        }else{
			        	cltSock = new Socket(this.ServerAddress, this.ServerPort);
			        	((Socket)cltSock).setSoTimeout(200);
			        	((Socket)cltSock).setReceiveBufferSize(2056);
			        	((Socket)cltSock).setSendBufferSize(2056);
			        	((Socket)cltSock).setKeepAlive(false);
			        	ServerHostandIP = ((Socket)cltSock).getRemoteSocketAddress().toString();
			        	if(ServerHostandIP != null && ServerHostandIP.indexOf(":") != -1){
			        		ServerHostandIP = ServerHostandIP.split(":")[0];
			        	}
			        	
			        	if(ServerHostandIP.indexOf('/')==0){
			        		ServerHostandIP = ServerHostandIP.split("/")[1];
						}
			        }
			        
			        DataOutputStream outToServer;
			        
			        InputStream inFromServer;
			        if(isSSL){
			        	outToServer = new DataOutputStream(((SSLSocket)cltSock).getOutputStream());
			        	inFromServer= ((SSLSocket)cltSock).getInputStream();
			        }else{
			        	outToServer = new DataOutputStream(((Socket)cltSock).getOutputStream());
			        	inFromServer= ((Socket)cltSock).getInputStream();
			        }
			        
			        
			       
			        
				        // Send data from client to server
				        SendData send = new SendData(this,true,false);
				        send.addEventListener(GenericMiTMServer.this);
				        send.addPyEventListener(this);
				        send.addSendClosedEventListener(this);
				        send.sock = connectionSocket;
				        send.in = inFromClient;
				        send.out = outToServer;
				        send.Name="c2s";
				        
				     // Send data from server to Client
				        SendData getD = new SendData(this,false,isSSL);
				        getD.addEventListener(GenericMiTMServer.this);
				        getD.addPyEventListener(this);
				        getD.addSendClosedEventListener(this);
				        getD.sock = cltSock;
				        getD.in=inFromServer;
				        getD.out=outToClient;
				        getD.Name="s2c";
				        
				        
				        sends.add(send);
				        sends.add(getD);
				        pairs.put(send, getD);
				        
				        
		
				        Thread c2s = new Thread(send);
				        Thread s2c = new Thread(getD);
				       
				        c2s.start();
				        s2c.start();
				        threads.add(c2s);
				        threads.add(s2c);
				        
			        
			        
			       
	        	}catch(ConnectException e){
	        		String message = e.getMessage();
	        		System.out.println(e.getMessage());
	        		if(message.equals("Connection refused"))
	        			Callbacks.printOutput( "Error: Connection Refused to "+  this.ServerAddress +":"+ this.ServerPort);
	        		else
	        			Callbacks.printOutput( e.getMessage() );
	        		connectionSocket.close();
	        	}

		        
		       
	        } 
	        connectionSocket.close();
    	}catch(Exception ex){
    		Callbacks.printOutput(ex.getMessage());
    		
    	}
    	Callbacks.printOutput("Main Thread Has Died but thats ok.");
    	isRunning=false;
		
	}
    

    
    public boolean isRunning(){
    	return this.isRunning;
    }
    
    public void setIntercept(boolean set){
    	this.isInterceptOn=set;
    }
    
    public boolean isInterceptOn(){
    	return this.isInterceptOn;
    }
    public void setInterceptDir(int direction){
    	this.IntercetpDirection = direction;
    }
    public int getIntercetpDir(){
    	return this.IntercetpDirection;
    }
    
    public void forwardC2SRequest(byte [] bytes){
    		//System.out.println("Forwarding Request...");
    		interceptc2s.setData(bytes);
    }
    public void forwardS2CRequest(byte [] bytes){
		//System.out.println("Forwarding Request...");
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
	
	private void KillSocks(SendData sd){
		//System.out.println(sd.Name);
		try{
			if(sd.isSSL()){
				/*((SSLSocket)sd.sock).shutdownInput();
				((SSLSocket)sd.sock).shutdownOutput();*/
				((SSLSocket)sd.sock).close();
			}else{
				/*((Socket)sd.sock).shutdownInput();
				((Socket)sd.sock).shutdownOutput();*/
				((Socket)sd.sock).close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			
		}
	}

	@Override
	public void Closed(SendClosedEvent e) {
		SendData tmp = (SendData)e.getSource();
		if(pairs.containsKey(tmp)){
			pairs.get(tmp).killme=true;
			//pairs.remove(tmp);
			
		}
		else if (pairs.containsValue(tmp)){
			for(SendData key : pairs.keySet()){
				if(pairs.get(key).equals(tmp)){
					key.killme=true;
					pairs.remove(key);
					KillSocks(tmp);
					KillSocks(key);
				}
			}
		}
		
		
	}


    
    
    
	








	
	
	
	
	
}


        




