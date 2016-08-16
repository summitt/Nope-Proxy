package josh.nonHttp;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;

import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
//import josh.nonHttp.utils.InterceptData;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;
import josh.utils.events.SendClosedEvent;
import josh.utils.events.SendClosedEventListener;

public class SendData implements Runnable{
	public InputStream in;
	public DataOutputStream out;
	public Object sock;
	public String Name;
	public boolean killme=false;
	private GenericMiTMServer SERVER;
	//private boolean isInterceptOn=true;
	private boolean isC2S;
	private boolean isSSL;
	private PythonMangler pm;
	//private Date lastaccess;
	
	
	public SendData(GenericMiTMServer srv, boolean isC2s, boolean isSSL){
		this.SERVER = srv;
		this.isC2S=isC2s;
		this.isSSL = isSSL;
	}
	
	private List _listeners = new ArrayList();
	private List _pylisteners = new ArrayList();
	private List _sclisteners = new ArrayList();
	
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
	public synchronized void addSendClosedEventListener(SendClosedEventListener listener)	{
		_sclisteners.add(listener);
	}
	public synchronized void removeSendClosedEventListener(SendClosedEventListener listener)	{
		_sclisteners.remove(listener);
	}
	public synchronized void SendClosedEventTrigger(){
		SendClosedEvent event = new SendClosedEvent(this);
		event.setDirection(this.Name);
		Iterator i = _sclisteners.iterator();
		while(i.hasNext())	{
			((SendClosedEventListener) i.next()).Closed(event);
		}
		
	}
	
	public synchronized void SendPyOutput(PythonMangler pm){
		String output = pm.getOutput();
		String error = pm.getError();
		if(!output.equals("") || !error.equals("")){
			PythonOutputEvent event = new PythonOutputEvent(this);
			event.setMessage(pm.getOutput());
			event.setError(pm.getError());
			if(isC2S){
				event.setDirection("Client-To-Server");
			}else{
				event.setDirection("Server-To-Client");
			}
			Iterator i = _pylisteners.iterator();
			while(i.hasNext())	{
				((PythonOutputEventListener) i.next()).PythonMessages(event);
			}
		}
	}
	private synchronized void NewDataEvent(byte [] data, byte[] original, String Direction)	{
		ProxyEvent event = new ProxyEvent(this);
		event.setData(data);
		event.setOriginalData(original);
		event.setDirection(Direction);
		if(Direction.contains("c2s")){
			if(isSSL){
				event.setSrcIP(this.getHostandIP(this.sock, true));//  ((SSLSocket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((SSLSocket)this.sock).getPort());
			}else{
				event.setSrcIP(this.getHostandIP(this.sock, false));//((Socket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((Socket)this.sock).getPort());
			}
			if(SERVER.ServerHostandIP != null && !SERVER.ServerHostandIP.trim().equals(""))
				event.setDstIP(SERVER.ServerHostandIP);
			else
				event.setDstIP(SERVER.ServerAddress);
			event.setDstPort(SERVER.ServerPort);
		}else{
			event.setDstIP(SERVER.connectionSocket.getInetAddress().getHostAddress());
			event.setDstPort(SERVER.connectionSocket.getPort());
			if(isSSL){
				event.setSrcIP(this.getHostandIP(this.sock, true));//((SSLSocket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((SSLSocket)this.sock).getPort());
			}else{	
				//String SourceInfo = this.getHostandIP(this.sock, false);
				event.setSrcIP(this.getHostandIP(this.sock, false));
				event.setSrcPort(((Socket)this.sock).getPort());
			}
		}
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			((ProxyEventListener) i.next()).DataReceived(event);
		}
	}
	private synchronized void Send2Interceptor(byte[] Data, String Direction, boolean isC2S)	{
		ProxyEvent event = new ProxyEvent(this);
		event.setData(Data);
		event.setDirection(Direction);
		if(Direction.contains("c2s")){
			if(isSSL){
				event.setSrcIP(this.getHostandIP(this.sock, true));//((SSLSocket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((SSLSocket)this.sock).getPort());
			}else{
				event.setSrcIP(this.getHostandIP(this.sock, false));//((Socket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((Socket)this.sock).getPort());
			}
			event.setDstIP(SERVER.ServerAddress);
			event.setDstPort(SERVER.ServerPort);
		}else{
			event.setDstIP(SERVER.connectionSocket.getInetAddress().getHostAddress());
			event.setDstPort(SERVER.connectionSocket.getPort());
			
			if(isSSL){
				event.setSrcIP(this.getHostandIP(this.sock, true));//((SSLSocket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((SSLSocket)this.sock).getPort());
			}else{
				event.setSrcIP(this.getHostandIP(this.sock, false));//((Socket)this.sock).getInetAddress().getHostAddress());
				event.setSrcPort(((Socket)this.sock).getPort());
			}
		}
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			((ProxyEventListener) i.next()).Intercepted(event, isC2S);
		}
	}
	
	public boolean isSSL(){
		return this.isSSL;
	}
	
	@Override
	public void run() {
		//System.out.println("new Send Data");
		while(true && !killme){
			
			int read=-1;
			try{
				if(Thread.interrupted()){
					//System.out.println("Thread Interrupted.");
					if(killme)
						break;
					
				}
				byte [] buffer = new byte[2056*1000]; //Buffer at most 2Meg
				//while((read = in.read(buffer, 0, buffer.length))!= -1 ){
				read = in.read(buffer, 0, buffer.length);
				//}

				
				
					if(read == -1)
						break; // we didn't read anything and the stream has ended.

					byte[] tmp = new byte[read];
					
					for(int i=0; i< read; i++){
						tmp[i]=buffer[i];
					}
					// Create an original buffer so we can check if things were modified
					byte[] original = tmp;
					
					// Check if we have enabled python modifications to the stream
					if(SERVER.isPythonOn()){
						pm = new PythonMangler();
						tmp = pm.mangle(tmp, isC2S);
						SendPyOutput(pm);
						// Check if we updated the data
						if(!Arrays.equals(tmp,original))
							this.Name = this.Name + " - Updated by Python (mangle)";
						
					}else{
						List<String>mtch = regexMatch();
						if(mtch != null){
							
							for(String line : mtch){
								
								//System.out.println(tmpStr);
								String []kv = line.split("\\|\\|");
								// Check for direction specific options
								String option = "both";
								if(kv.length == 3){
									option = kv[2];
								}
								if(option.equals("both")){
									//Do nothing and let the rest process
								}else if(option.equals("c2sOnly") && this.isC2S){
									//Do nothing and let the rest process
								}else if(option.equals("s2cOnly") && !this.isC2S){
									//Do nothing and let the rest process
								}else{
									// return to for loop
									continue;
								}
								
								if(kv[0].startsWith("#")){
									//do nothing this is a comment
								}
								else if(kv[0].startsWith("0x")){ 
									// This indicates we are doing hex replacement
									byte [] match = new BigInteger(kv[0].replace("0x", ""),16).toByteArray();
									byte [] replace = new BigInteger(kv[1].replace("0x", ""),16).toByteArray();
									tmp = this.replace(tmp, match, replace);
								}else{
									// this will be just a basic string replacement
									byte [] match = kv[0].getBytes();
									byte [] replace = kv[1].getBytes();
									tmp = this.replace(tmp, match, replace);
								}	
							}
							if(!Arrays.equals(tmp,original))
								this.Name = this.Name + " - Updated by Match And Replace Rules";
						}
					}
					
					// Send things to the interceptor if it is enabled
					if(SERVER.isInterceptOn()){
						if(SERVER.getIntercetpDir() == SERVER.INTERCEPT_BOTH || 
								(this.Name.equals("c2s") && SERVER.getIntercetpDir() == SERVER.INTERCEPT_C2S) ||
								(this.Name.equals("s2c") && SERVER.getIntercetpDir() == SERVER.INTERCEPT_S2C)
								){
							// Here we format the data before sending it to the interceptor
							if(SERVER.isPythonOn()){
								tmp = pm.preIntercept(tmp, isC2S);
								SendPyOutput(pm);
							}
							if(!Arrays.equals(tmp,original))
								this.Name = this.Name + " - Formated by Python";
							// This will block until the the request if forwarded by the user from the interceptor
							// This function also handles the events that send the informatoin to the UI and logs.
							Send2Interceptor(tmp, this.Name, isC2S); 
							
							if(isC2S)
								tmp=SERVER.interceptc2s.getData();
							else
								tmp=SERVER.intercepts2c.getData();
							
							// Here we format the data back before sending it back
							if(SERVER.isPythonOn()){
								tmp = pm.postIntercept(tmp, isC2S);
								SendPyOutput(pm);
							}
							
						}else{
							// Data was not manually intercepted so we treat it like a normal event.
							NewDataEvent(tmp, original, this.Name);
						}
					}else{
						// Manual Intercepts was not enabled so we treat it like a normal event.
						NewDataEvent(tmp, original, this.Name);
					}
					
					//Write the data back to the socket
					out.write(tmp);
					
				
				
			}catch(SocketTimeoutException Ex){
			}catch(SSLHandshakeException Ex){
				System.out.println(Ex.getMessage());
			}catch(SSLException Ex){
				//System.out.println(Ex.getMessage());
			}
			catch(Exception Ex){
				System.out.println("Error in: " + this.Name);
				Ex.printStackTrace(); 
				break;
				
				
				}
			
		}
		System.out.println(this.Name + " - Connection Has Closed.");
		this.SendClosedEventTrigger();
		//System.out.println("Socket Closed.");
		
		
	}
	
	
	////Fun Functions 
	private String getHostandIP(Object Socket, boolean isSSL){
		String SourceInfo=""; 
		if(isSSL){
			SourceInfo = ((SSLSocket)Socket).getRemoteSocketAddress().toString();
		}else
			SourceInfo = ((Socket)Socket).getRemoteSocketAddress().toString();
		
		
		if(SourceInfo != null && SourceInfo.indexOf(":") != -1 && !this.isIPV6(SourceInfo)){
			
			SourceInfo = SourceInfo.split(":")[0];
			if(SourceInfo.indexOf('/')==0){
				SourceInfo = SourceInfo.split("/")[1];
			}
		}else{
			if(isSSL){
				SourceInfo = ((SSLSocket)Socket).getInetAddress().getHostAddress();
			}else
				SourceInfo = ((Socket)Socket).getInetAddress().getHostAddress();
		}
		
		return SourceInfo;
	}
	
	private boolean isIPV6(String addr){
		if(countchars(addr, ':') > 1)
			return true;
		else
			return false;
	}
	
	private int countchars(String arg, char c){
		int count = 0;
		for(int i = 0; i< arg.length(); i++){
			if( arg.charAt(i) == c){
				count++;
			}
		}
		return count;
	}
	
	private  List<String> regexMatch(){
		List<String> tmp = new ArrayList<String>();
		String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
		File f = new File(file);
		if(!f.exists()){
			System.out.println("missing nonHTTPmatch.txt");
			return new ArrayList<String>();
		}
		Path p = Paths.get(file);
		//if(isC2S){
			Charset charset = Charset.forName("UTF-8");
			try (BufferedReader reader = Files.newBufferedReader(p, charset)) {
			    String line = null;
			    while ((line = reader.readLine()) != null) {
			    	tmp.add(line);
			    }
			} catch (IOException x) {
			    System.err.format("IOException: %s%n", x);
			}
		//}
		return tmp;
	}
	
	private  byte [] replace(byte[] input, byte [] match, byte [] replace) throws IOException{
		ByteArrayOutputStream bos = new ByteArrayOutputStream( );
		byte [] tmp = input;
		int length = tmp.length;
		int offset=0;
		for(int i=0;i<length; i++){
			if(lookahead(i, tmp, match)){
				//bos.write(tmp, offset, i-offset);
				bos.write(replace);
				offset=i+match.length;
				i=i+match.length-1;
			}else{
				bos.write(tmp[i]);
			}
		}
		return bos.toByteArray();
		
	}
	
	private  boolean lookahead(int index, byte [] input, byte [] match){
		int j = 0;
		for(int i=index; i < input.length && j < match.length; i++){
			if(input[i] != match[j++]){
				return false;
			}
		}
		if(j == match.length)
			return true;
		else 
			return false;
	}
	
	
}

