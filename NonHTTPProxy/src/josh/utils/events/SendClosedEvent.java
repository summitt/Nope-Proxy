package josh.utils.events;

import java.util.EventObject;

public class SendClosedEvent extends EventObject  {
	

	private String direction;

	public SendClosedEvent(Object arg0) {
		super(arg0);
	}

	public String getDirection() {
		return direction;
	}

	public void setDirection(String direction) {
		this.direction = direction;
	}


	
	

}
