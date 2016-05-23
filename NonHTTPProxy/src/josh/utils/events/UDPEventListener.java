package josh.utils.events;

import java.util.EventListener;

public interface UDPEventListener extends EventListener {
	 public abstract void UDPDown(DNSEvent e);

}
