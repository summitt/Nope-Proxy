package josh.nonHttp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.python.core.PyBoolean;
import org.python.core.PyByteArray;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

public class PythonMangler {
	private String pyCode;
	private PythonInterpreter interpreter;
	
	public PythonMangler(){
			
			
			String fs =  System.getProperty("file.separator");
			String file = System.getProperty("user.dir") + fs  +"mangler.py";
			/*Properties props = new Properties();
			System.out.println(System.getProperty("python.path"));
			props.setProperty("python.path", System.getProperty("user.dir"));
			PythonInterpreter.initialize(System.getProperties(), props,
                    new String[] {""});*/
			
			this.interpreter = new PythonInterpreter();
			//TODO: Add output steam to this so that we can log errors to the console. 
			interpreter.setOut(System.out);
			interpreter.setErr(System.err);
			
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
			/*pyCode="import sys\r\nsys.path.append('" + System.getProperty("user.dir") + "')\r\n"
					+ "libs=['C:\\Python27\\Lib\\site-packages', 'C:\\Python27\\Lib\\site-packages\\pypcap-1.1.5-py2.7-win32.egg', 'C:\\WINDOWS\\SYSTEM32\\python27.zip', 'C:\\Python27\\DLLs', 'C:\\Python27\\Lib', 'C:\\Python27\\Lib\\plat-win', 'C:\\Python27\\Lib\\lib-tk', 'C:\\Python27']\r\n"
					+ "for lib in libs:\r\n"
					+ "   sys.path.append(lib)\r\n\r\n"
					+ "print sys.path\r\n";*/
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
	public byte [] preIntercept(byte [] input, boolean isC2S){
		//PythonInterpreter interpreter = new PythonInterpreter();
		//interpreter.exec(pyCode);
		PyObject someFunc = interpreter.get("preIntercept");
		//this means that the pre Intercept feature has not been implemented.
		if(someFunc == null)
			return input;
		PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
		PyByteArray array = (PyByteArray) result.__tojava__(Object.class);
		byte[] out = new byte [array.__len__()];
		for(int i=0; i < array.__len__(); i++){
			out[i] = (byte)array.get(i).__tojava__(Byte.class);
		}
		
		return out;
	}
	public byte [] postIntercept(byte [] input, boolean isC2S){
		//PythonInterpreter interpreter = new PythonInterpreter();
		//TODO: this might not work as expected
		//interpreter.exec(pyCode);  
		PyObject someFunc = interpreter.get("postIntercept");
		//this means that the pre Intercept feature has not been implemented.
		if(someFunc == null)
			return input;
		PyObject result = someFunc.__call__(new PyByteArray(input), new PyBoolean(isC2S));
		PyByteArray array = (PyByteArray) result.__tojava__(Object.class);
		byte[] out = new byte [array.__len__()];
		for(int i=0; i < array.__len__(); i++){
			out[i] = (byte)array.get(i).__tojava__(Byte.class);
		}
		
		return out;
	}
	
	public byte [] mangle(byte [] input, boolean isC2S){
		//PythonInterpreter interpreter = new PythonInterpreter();
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
