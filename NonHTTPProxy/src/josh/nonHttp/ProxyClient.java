package josh.nonHttp;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public class ProxyClient implements Runnable{
	
	private String IP;
	private int Port;
	private byte[] Data;

	@Override
	public void run() {
		System.out.println("New CLient");
		Socket clientSocket= null;;
		try {
			clientSocket = new Socket(this.IP, this.Port);
		
			DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
			InputStream inFromServer = clientSocket.getInputStream();
			outToServer.write(this.Data, 0, this.Data.length);
			byte[] buffer = new byte[1024];
			int read=0;
			while ((read = inFromServer.read(buffer)) != -1) {
				System.out.println(""+read);
				byte[] buff = new byte[read];
				
				for(int i=0; i<read;i++)
					buff[i]=buffer[i];
	
				
			}
			//ToDO: fire Event
	
			clientSocket.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			if(clientSocket != null)
				try {
					clientSocket.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		
	}
	
	public void setPort(int port){
		this.Port=port;
	}
	public void setIP(String IP){
		this.IP=IP;
	}
	
	public void setData(byte [] Data){
		this.Data=Data;
	}

}
