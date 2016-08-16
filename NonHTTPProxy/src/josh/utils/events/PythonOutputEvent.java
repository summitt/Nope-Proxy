package josh.utils.events;

import java.util.EventObject;

public class PythonOutputEvent extends EventObject  {
	
	private String Message;
	private String Error;
	private String Direction;

	public PythonOutputEvent(Object arg0) {
		super(arg0);
	}

	public String getMessage() {
		return Message;
	}

	public void setMessage(String message) {
		Message = message;
	}

	public String getError() {
		return Error;
	}

	public void setError(String error) {
		Error = error;
	}

	public String getDirection() {
		return Direction;
	}

	public void setDirection(String direction) {
		Direction = direction;
	}
	
	

	
	
	

}
