package josh.nonHttp.events;


public interface ProxyEventListener {
	 public abstract void DataReceived(ProxyEvent e);
	 public abstract void Intercepted(ProxyEvent e, boolean isC2S);

}
