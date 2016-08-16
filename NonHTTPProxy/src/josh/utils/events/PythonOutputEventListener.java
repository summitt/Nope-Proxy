package josh.utils.events;

import java.util.EventListener;

public interface PythonOutputEventListener extends EventListener {
	
	 public abstract void PythonMessages(PythonOutputEvent e);
	
}
