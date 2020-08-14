package josh.dao;


import java.util.Properties;

import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

public class HibHelper {
	


	
	 private static SessionFactory sessionFactory = buildSessionFactory();

	    private static SessionFactory buildSessionFactory() {
	    	System.out.println("Built new session factory");
	    	//java.util.logging.Logger.getLogger("org.hibernate").setLevel(java.util.logging.Level.OFF);
	    	//java.util.logging.Logger.getLogger("com.mchange").setLevel(java.util.logging.Level.OFF);
	        try {
	        	String path = System.getProperty("user.home");
				String resultFile = path + "/.NoPEProxy/requests.sqlite";
	        	String SQLString =  "jdbc:sqlite:" + resultFile;
				Configuration cfg = new Configuration();
				Properties prop= new Properties();

				prop.setProperty("hibernate.dialect", "josh.dao.SQLiteDialect");
				prop.setProperty("hibernate.connection.driver_class", "org.sqlite.JDBC");
				prop.setProperty("hibernate.show_sql", "false");
				prop.setProperty("hibernate.hbm2ddl.auto", "update"); 
				prop.setProperty("hibernate.c3p0.min_size", "20"); 
				prop.setProperty("hibernate.c3p0.max_size", "50"); 
				prop.setProperty("hibernate.c3p0.timeout", "1800"); 
				prop.setProperty("hibernate.c3p0.max_statements", "300"); 
				prop.setProperty("hibernate.c3p0.idle_test_period", "300"); 
				prop.setProperty("hibernate.connection.url",SQLString);
				cfg.addProperties(prop);

				cfg.addAnnotatedClass(Requests.class);
				cfg.addAnnotatedClass(ListenerSetting.class);

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
