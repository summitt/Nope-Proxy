package josh.utils.events;

import java.util.EventListener;

public interface TcpDumpListener extends EventListener{
	 public abstract void NewPort(DNSEvent e);
	 public abstract void SnifferDown(DNSEvent e);
	

}
