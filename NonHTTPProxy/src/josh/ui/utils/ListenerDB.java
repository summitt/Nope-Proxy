package josh.ui.utils;


import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import org.hibernate.Session;
import josh.dao.HibHelper;
import josh.dao.ListenerSetting;
import josh.dao.Requests;

public class ListenerDB
{
   

    
   
   
    public static void add(ListenerSetting ls){
    	Session s = HibHelper.getSessionFactory().openSession();
    	s.getTransaction().begin();
    	s.save(ls);
    	s.getTransaction().commit();
    	s.close();
    	
    }
    public static void updateSSL(ListenerSetting ls, boolean ssl){
    	Session s = HibHelper.getSessionFactory().openSession();
    	List<ListenerSetting> list = (List<ListenerSetting>)s
    			.createQuery("from ListenerSetting where sip = :sip and sport = :sport and lport = :lport and cert = :cert and ssl = :ssl")
    			.setParameter("sip", ls.getSip())
    			.setParameter("sport", ls.getSport())
    			.setParameter("lport", ls.getLport())
    			.setParameter("cert", ls.getCert())
    			.setParameter("ssl", ls.isSsl())
    			.list();
    	if(list.size() >= 1){
    		s.getTransaction().begin();
    		list.get(0).setSsl(ssl);
    		s.update(list.get(0));
    		s.getTransaction().commit();
    	}
    	s.close();
    	
    }
    public static void remove(ListenerSetting ls){
    	Session s = HibHelper.getSessionFactory().openSession();
    	List<ListenerSetting> list = (List<ListenerSetting>)s
    			.createQuery("from ListenerSetting where sip = :sip and sport = :sport and lport = :lport and cert = :cert and ssl = :ssl")
    			.setParameter("sip", ls.getSip())
    			.setParameter("sport", ls.getSport())
    			.setParameter("lport", ls.getLport())
    			.setParameter("cert", ls.getCert())
    			.setParameter("ssl", ls.isSsl())
    			.list();
    	if(list.size() >= 1){
    		s.getTransaction().begin();
    		s.delete(list.get(0));
    		s.getTransaction().commit();
    	}
    	s.close();
    }
   
    
    
    public static List<ListenerSetting>restoreDB(){
    	//HibHelper.getSessionFactory().openSession();
    	
    	Session s = HibHelper.getSessionFactory().openSession();
    	List<ListenerSetting> list = (List<ListenerSetting>)s.createQuery("from ListenerSetting").list();
    	s.close();
    	return list;
    	
    }
    
    
}