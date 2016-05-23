package josh.utils.events;

import java.util.EventListener;

public interface DNSConfigListener extends EventListener {
	
	 public abstract void DNSToggle(DNSEvent e);
	 //public abstract void StopSniffer(DNSEvent e);
	 //public abstract void StartSniffer(DNSEvent e);
	
}
