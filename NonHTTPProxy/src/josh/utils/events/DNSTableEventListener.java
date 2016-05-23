package josh.utils.events;

import java.util.EventListener;

public interface DNSTableEventListener extends EventListener{
	
	public abstract void NewDomainRequest(DNSTableEvent e);

}
