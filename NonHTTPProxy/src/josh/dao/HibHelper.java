package josh.dao;


import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

public class HibHelper {
	
	 private static final SessionFactory sessionFactory = buildSessionFactory();

	    private static SessionFactory buildSessionFactory() {
	    	java.util.logging.Logger.getLogger("org.hibernate").setLevel(java.util.logging.Level.OFF);
	    	java.util.logging.Logger.getLogger("com.mchange").setLevel(java.util.logging.Level.OFF);
	        try {
	           
	            return new Configuration().configure().buildSessionFactory();
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
	
	

}
