package josh.utils.events;

import java.util.EventListener;

public interface SendClosedEventListener extends EventListener {
	
	 public abstract void Closed(SendClosedEvent e);
	
}
