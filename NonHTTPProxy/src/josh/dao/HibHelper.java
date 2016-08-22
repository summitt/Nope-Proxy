package josh.dao;


import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

public class HibHelper {
	
	 private static SessionFactory sessionFactory = buildSessionFactory();

	    private static SessionFactory buildSessionFactory() {
	    	java.util.logging.Logger.getLogger("org.hibernate").setLevel(java.util.logging.Level.OFF);
	    	java.util.logging.Logger.getLogger("com.mchange").setLevel(java.util.logging.Level.OFF);
	        try {
	        	String path = System.getProperty("user.home");
				String resultFile = path + "/.NoPEProxy/requests.sqlite";
	        	String SQLString =  "jdbc:sqlite:" + resultFile;
	        	Configuration cfg = new Configuration();
	        	cfg.configure(); 
	        	cfg.getProperties().setProperty("hibernate.connection.url",SQLString);
	            return cfg.buildSessionFactory();
	        }
	        catch (Throwable ex) {
	            // Make sure you log the exception, as it might be swallowed
	            System.err.println("Initial SessionFactory creation failed." + ex);
	            throw new ExceptionInInitializerError(ex);
	        }
	    }

	    public static SessionFactory getSessionFactory() {
	        return sessionFactory;
	    }
	    
	    public static void renew(){
	    	sessionFactory = buildSessionFactory();
	    }
	
	

}
