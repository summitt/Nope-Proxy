package josh.utils;
import org.apache.commons.codec.binary.Hex;

public class PayloadAnalysis {
	
	public static String createPyCode(byte [] request){
		
		String payload = "payload='";
		for(int i=0; i< request.length; i++){
			
			String test = ""+(char)request[i];
			//System.out.println(test);
			if( test.matches("[a-zA-Z0-9~!@#$%^&*()_+`\\-\\=;':\",./<>?\\\\|\\ ]")){
				payload+=test;
			}else{
				byte [] bArray = new byte []{request[i]};
				payload+="\\x"+Hex.encodeHex( bArray)[0] + Hex.encodeHex( bArray)[1];
			}
		}
		payload +="'";
		return payload;
		
	}

}
