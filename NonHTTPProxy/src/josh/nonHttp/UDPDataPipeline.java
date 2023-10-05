package josh.nonHttp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;


import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;
import josh.utils.events.SendClosedEvent;
import josh.utils.events.SendClosedEventListener;
import java.io.ByteArrayOutputStream;

public class UDPDataPipeline implements Runnable {

    private List _listeners = new ArrayList();
    private List _pylisteners = new ArrayList();
    private List _sclisteners = new ArrayList();
    private String Name = "";
    private Boolean isC2S = true;
    private String dstIPString;
    private int dstPort;
    private int srcPort;
    private String srcIPString;
    private InetAddress dstIP;
    private PythonMangler mangler = new PythonMangler();
    private byte[] originalBuffer;
    private byte[] modifiedBuffer;
    private String direction = "";
    private GenericUDPMiTMServer udpServer;

    public UDPDataPipeline(GenericUDPMiTMServer udpServer, byte[] buffer, InetAddress srcIp, int srcPort,
            InetAddress dstIp, int dstPort, boolean isC2S) {
        this.originalBuffer = buffer.clone();
        this.modifiedBuffer = buffer.clone();
        this.srcIPString = srcIp.getHostAddress();
        this.dstIPString = dstIp.getHostAddress();
        this.dstIP = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.isC2S = isC2S;
        this.udpServer = udpServer;
        if(isC2S){
            this.Name = "c2s";
        }else{
            this.Name = "s2c";
        }
    }

    @Override
	public void run() {
        // Check if we have enabled python modifications to the stream
        if (this.udpServer.isPythonOn()) {
            this.updateBufferWithManger();
        } else {
            this.updateBuffersWithRegEx();
        }

        Boolean interceptTestPassed = true;
        if(this.udpServer.isInterceptOn()){
            if (this.udpServer.isPythonOn()) {
                interceptTestPassed = this.mangler.interceptRules(this.modifiedBuffer, isC2S);
                SendPyOutput(mangler);
            }
        }
		if (this.udpServer.isInterceptOn() && interceptTestPassed) {
            this.updateBufferWithInterceptors();
        }else{
            // Manual Intercepts was not enabled so we treat it like a normal event.
            /*if (this.udpServer.isPythonOn()) {
                ///This will format only and not chang the actual datqa
                byte [] updated = this.mangler.formatOnly(this.modifiedBuffer, this.isC2S);
                NewDataEvent(updated);
            }else{*/
                NewDataEvent(this.modifiedBuffer);
            //}
        }

        try {
            DatagramPacket serverRequest = new DatagramPacket(this.modifiedBuffer, this.modifiedBuffer.length, this.dstIP, this.dstPort);
            this.udpServer.udpServerSocket.send(serverRequest);
        }catch(IOException ex){
            System.out.println(ex);
        }



    }

    // Utility Functions

    private void updateBufferWithInterceptors(){

        if (this.udpServer.getIntercetpDir() == this.udpServer.INTERCEPT_BOTH ||
                (this.Name.contains("c2s") && this.udpServer.getIntercetpDir() == this.udpServer.INTERCEPT_C2S) ||
                (this.Name.contains("s2c") && this.udpServer.getIntercetpDir() == this.udpServer.INTERCEPT_S2C)) {
            // Here we format the data before sending it to the interceptor
            if (this.udpServer.isPythonOn()) {
                this.modifiedBuffer = this.mangler.preIntercept(this.modifiedBuffer, this.isC2S);
                SendPyOutput(this.mangler);
            }
            //TODO: This logic is not totally right. The data could be altered by other tools before this step.
            if (!Arrays.equals(this.modifiedBuffer, this.originalBuffer)){
                if(!this.Name.contains("Formated")){
                    this.Name = this.Name + " - Formated by Python";
                }
            }else{
                this.Name = this.Name.replace(" - Formated by Python", "");
            }
            // This will block until the the request if forwarded by the user from the
            // interceptor
            // This function also handles the events that send the informatoin to the UI and
            // logs.
            Send2Interceptor(this.modifiedBuffer);

            if (isC2S)
                this.modifiedBuffer =  this.udpServer.interceptc2s.getData();
            else
                this.modifiedBuffer = this.udpServer.intercepts2c.getData();

            // Manual Intercepts was not enabled so we treat it like a normal event.
            if (this.udpServer.isPythonOn()) {
                ///This will format only and not chang the actual datqa
                byte [] updated = this.mangler.formatOnly(this.modifiedBuffer, this.isC2S);
                NewDataEvent(updated);
            }else{
                NewDataEvent(this.modifiedBuffer);
            }

        } else {
            // Manual Intercepts was not enabled so we treat it like a normal event.
            if (this.udpServer.isPythonOn()) {
                ///This will format only and not chang the actual datqa
                byte [] updated = this.mangler.formatOnly(this.modifiedBuffer, this.isC2S);
                NewDataEvent(updated);
            }else{
                NewDataEvent(this.modifiedBuffer);
            }
        }
    }

    private void updateBufferWithManger(){
        System.out.println("manglin");
        mangler.reload();
        this.modifiedBuffer = mangler.mangle(this.modifiedBuffer, isC2S);
        SendPyOutput(mangler);
        // Check if we updated the data
        if (!Arrays.equals(this.modifiedBuffer, this.originalBuffer)){
            if(!this.Name.contains("mangle")){
                this.Name = this.Name + " - Updated by Python (mangle)";
            }
        }else{
            this.Name = this.Name.replace(" - Updated by Python (mangle)", "");
        }
    }
    private List<String> regexMatch() {
        List<String> tmp = new ArrayList<String>();
        /*
         * String fs = System.getProperty("file.separator");
         * String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
         */
        String path = System.getProperty("user.home");
        String file = path + "/.NoPEProxy/nonHTTPmatch.txt";
        File f = new File(file);
        if (!f.exists()) {
            System.out.println("missing nonHTTPmatch.txt");
            return new ArrayList<String>();
        }
        Path p = Paths.get(file);
        // if(isC2S){
        Charset charset = Charset.forName("UTF-8");
        try (BufferedReader reader = Files.newBufferedReader(p, charset)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                tmp.add(line);
            }
        } catch (IOException x) {
            System.err.format("IOException: %s%n", x);
        }
        // }
        return tmp;
    }

    private void updateBuffersWithRegEx(){
            try{
                List<String> mtch = regexMatch();
                if (mtch != null) {

                    for (String line : mtch) {

                        String[] kv = line.split("\\|\\|");
                        // Check for direction specific options
                        String option = "both";
                        if (kv.length == 3) {
                            option = kv[2];
                        }
                        if (option.equals("both")) {
                            // Do nothing and let the rest process
                        } else if (option.equals("c2sOnly") && this.isC2S) {
                            // Do nothing and let the rest process
                        } else if (option.equals("s2cOnly") && !this.isC2S) {
                            // Do nothing and let the rest process
                        } else {
                            // return to for loop
                            continue;
                        }

                        if (kv[0].startsWith("#")) {
                            // do nothing this is a comment
                        } else if (kv[0].startsWith("0x")) {
                            // This indicates we are doing hex replacement
                            byte[] match = new BigInteger(kv[0].replace("0x", ""), 16).toByteArray();
                            byte[] replace = new BigInteger(kv[1].replace("0x", ""), 16).toByteArray();
                            this.modifiedBuffer = this.replace(this.modifiedBuffer, match, replace);
                        } else {
                            // this will be just a basic string replacement
                            byte[] match = kv[0].getBytes();
                            byte[] replace = kv[1].getBytes();
                            this.modifiedBuffer = this.replace(this.modifiedBuffer, match, replace);
                        }
                    }
                    if (!Arrays.equals(this.modifiedBuffer, this.originalBuffer)){
                        if(!this.Name.contains("Match")){
                            this.Name = this.Name + " - Updated by Match And Replace Rules";
                        }
                    }else
                        this.Name = this.Name.replace(" - Updated by Match And Replace Rules", "");
                }
            }catch(IOException ex){
                System.out.println(ex);
            }
    }

	private byte[] replace(byte[] input, byte[] match, byte[] replace) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] tmp = input;
		int length = tmp.length;
		int offset = 0;
		for (int i = 0; i < length; i++) {
			if (lookahead(i, tmp, match)) {
				// bos.write(tmp, offset, i-offset);
				bos.write(replace);
				offset = i + match.length;
				i = i + match.length - 1;
			} else {
				bos.write(tmp[i]);
			}
		}
		return bos.toByteArray();

	}

	private boolean lookahead(int index, byte[] input, byte[] match) {
		int j = 0;
		for (int i = index; i < input.length && j < match.length; i++) {
			if (input[i] != match[j++]) {
				return false;
			}
		}
		if (j == match.length)
			return true;
		else
			return false;
	}

    /// All Event Stuff

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

    public synchronized void addSendClosedEventListener(SendClosedEventListener listener) {
        _sclisteners.add(listener);
    }

    public synchronized void removeSendClosedEventListener(SendClosedEventListener listener) {
        _sclisteners.remove(listener);
    }

    public synchronized void SendClosedEventTrigger() {
        SendClosedEvent event = new SendClosedEvent(this);
        event.setDirection(this.Name);
        Iterator i = _sclisteners.iterator();
        while (i.hasNext()) {
            ((SendClosedEventListener) i.next()).Closed(event);
        }

    }

    public synchronized void SendPyOutput(PythonMangler pm) {
        String output = pm.getOutput();
        String error = pm.getError();
        if (!output.equals("") || !error.equals("")) {
            PythonOutputEvent event = new PythonOutputEvent(this);
            event.setMessage(output);
            event.setError(error);
            if (isC2S) {
                event.setDirection("Client-To-Server");
            } else {
                event.setDirection("Server-To-Client");
            }
            Iterator i = _pylisteners.iterator();
            while (i.hasNext()) {
                ((PythonOutputEventListener) i.next()).PythonMessages(event);
            }
        }
    }

    private synchronized void NewDataEvent(byte[] modified) {
        ProxyEvent event = new ProxyEvent(this);
        event.setProtocl("UDP");
        event.setData(modified);
        event.setOriginalData(this.originalBuffer);
        event.setDirection(this.Name);
        event.setSrcIP(this.srcIPString);
        event.setSrcPort(this.srcPort);
        event.setDstIP(this.dstIPString);
        event.setDstPort(this.dstPort);
        event.setMtm(this.udpServer);
        Iterator i = _listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).DataReceived(event);
        }
    }

    private synchronized void Send2Interceptor(byte[] data) {
        ProxyEvent event = new ProxyEvent(this);
        event.setProtocl("UDP");
        event.setData(data);
        event.setDirection(this.Name);
        event.setSrcIP(this.srcIPString);
        event.setSrcPort(this.srcPort);
        event.setDstIP(this.dstIPString);
        event.setDstPort(this.dstPort);
        Iterator i = _listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).Intercepted(event, this.isC2S);
        }
    }

}
