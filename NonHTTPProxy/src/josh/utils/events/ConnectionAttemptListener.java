package josh.utils.events;

import java.util.EventListener;

public interface  ConnectionAttemptListener extends EventListener {
	
	public abstract void ConnectAttempt(PortConnectEvt pkt);

}
