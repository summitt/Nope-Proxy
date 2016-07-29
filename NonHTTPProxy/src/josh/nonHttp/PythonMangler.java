package josh.nonHttp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.python.core.PyBoolean;
import org.python.core.PyByteArray;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

public class PythonMangler {
	private String pyCode;
	
	public PythonMangler(){
			String fs =  System.getProperty("file.separator");
			String file = System.getProperty("user.dir") + fs + "mangler.py";
			File f = new File(file);
			if(!f.exists()){
				try {
					f.createNewFile();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
			}
			Path p = Paths.get(file);
			
			BufferedReader reader;
			pyCode="";
			try {
				reader = Files.newBufferedReader(p);
				
				String line="";
				while ((line = reader.readLine()) != null) {
					pyCode+=line+"\r\n";
				}
				if(pyCode.trim().equals("")){
					pyCode= "def mangle(input, isC2S):\r\n";
					pyCode+="\treturn input";
					p = Paths.get(file);
					Charset charset = Charset.forName("UTF-8");
					try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
						writer.write(pyCode);
					}catch(Exception ex){
						ex.printStackTrace();
					}
				}
			} catch (IOException e) {
				pyCode="";
				e.printStackTrace();
			}
	}
	
	public String getPyCode(){
		return pyCode;
	}
	public String setPyCode(String code){
		String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "mangler.py";
		File f = new File(file);
		this.pyCode = code;
		if(pyCode.trim().equals("")){
			pyCode= "def mangle(input, isC2S):\r\n";
			pyCode+="\treturn input";
		}
		Path p = Paths.get(file);
		Charset charset = Charset.forName("UTF-8");
		try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
			writer.write(pyCode);
		}catch(Exception ex){
			ex.printStackTrace();
		}
		return this.pyCode;
			
	}
	
	public byte [] mangle(byte [] input, boolean isC2S){
		PythonInterpreter interpreter = new PythonInterpreter();
		interpreter.exec(pyCode);
		PyObject someFunc = interpreter.get("mangle");
		PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
		PyByteArray array = (PyByteArray) result.__tojava__(Object.class);
		byte[] out = new byte [array.__len__()];
		for(int i=0; i < array.__len__(); i++){
			out[i] = (byte)array.get(i).__tojava__(Byte.class);
		}
		
		return out;
	}
	
	
	//Test function
	 public static void main(String[] args) {
		 PythonMangler pm = new PythonMangler();
		 byte []out = pm.mangle("test this shit".getBytes(), true);
		 System.out.println(new String(out));
		    
	 }

}
