package josh.utils.events;

import java.util.EventListener;

public interface  TCPConnectionAttemptListener extends EventListener {
	
	public abstract void TcpConnAttempt(TCPPacketEvt pkt);

}
