package josh.utils;

public class SharedBoolean {
	 private volatile boolean useDefault = false;
	 
	 public void setDefault(boolean defaultVar){
		 this.useDefault = defaultVar;
	 }
	 
	 public boolean getDefault(){
		 return this.useDefault;
	 }
	 
	 

}
