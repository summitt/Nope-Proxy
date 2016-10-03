package josh.ui.utils;

public class InterceptData {
	private byte [] Data;
	
	public InterceptData(byte [] data){
		this.Data = data;
	}
	
	public byte [] getData(){
		return Data;
	}
	
	public void setData(byte [] data){
		this.Data = data;
	}

}
