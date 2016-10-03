package josh.ui.utils;


import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import org.hibernate.Session;
import josh.dao.HibHelper;
import josh.dao.Requests;

public class LogEntry
{
    final Date time;
    byte[] requestResponse;
    final int SrcPort;
    final int DstPort;
    final String SrcIP;
    final String DstIP;
    final String Direction;
    final int Bytes;
    Long Index;
    byte [] original; 


    
    public LogEntry(byte[] requestResponse, byte[] original, String SrcIp,int SrcPort, String DstIP, int DstPort, String Direction)
    {
    	
        this.time = Calendar.getInstance().getTime();
        this.requestResponse = requestResponse;
        this.original=original;
        this.SrcIP = SrcIp;
        this.DstIP = DstIP;
        this.SrcPort = SrcPort;
        this.DstPort = DstPort;
        this.Direction = Direction;
        this.Bytes = requestResponse.length;

        
    }
    
    public LogEntry(Long Index, String SrcIp,int SrcPort, String DstIP, int DstPort, String Direction, Long time, int bytes)
    {

    	this.Index = Index;
        this.time = new Date(time);
        this.SrcIP = SrcIp;
        this.DstIP = DstIP;
        this.SrcPort = SrcPort;
        this.DstPort = DstPort;
        this.Direction = Direction;
        this.Bytes = bytes;
       
        
    }
    public boolean canAdd(String term){
    	if(term==null || term.trim().equals(""))
    		return true;
    	else if( new String(requestResponse).contains(term.trim()))
    		return true;
    	else if(new String(original).contains(term.trim()))
    		return true;
    	else 
    		return false;
    }
    public long save(){
    	Session s = HibHelper.getSessionFactory().openSession();
    	Requests dao = new Requests(0, this.requestResponse, this.original, this.SrcIP, this.SrcPort, this.DstIP, this.DstPort, this.Direction, this.time.getTime(), this.Bytes);
    	s.getTransaction().begin();
    	s.save(dao);
    	s.getTransaction().commit();
    	s.close();
    	this.Index = (long)dao.getId();
    	return dao.getId();
    	
    	
    }
    public static void clearTable(){
    	
    	Session s = HibHelper.getSessionFactory().openSession();
    	s.getTransaction().begin();
    	s.createQuery("delete from Requests").executeUpdate();
    	//reset index
    	s.createSQLQuery("update hibernate_sequence set next_val = 1").executeUpdate();
    	s.getTransaction().commit();
    	
    	s.close();
    	
    }
    public Requests getData(Long index){
    	Session s = HibHelper.getSessionFactory().openSession();
    	Requests r = (Requests)s.createQuery("from Requests where id = :id").setInteger("id", index.intValue()).uniqueResult();
    	s.close();
    	return r;
    }
    
    public static LinkedList<LogEntry>restoreDB(){
    	//HibHelper.getSessionFactory().openSession();
    	
    	Session s = HibHelper.getSessionFactory().openSession();
    	List<Requests> r = (List<Requests>)s.createQuery("from Requests order by id desc").list();
    	LinkedList<LogEntry> list = new LinkedList<LogEntry>();
    	for(Requests q : r){
    		list.add(new LogEntry((long)q.getId(), q.getSrcIp(), q.getSrcPort(), q.getDstIp(), q.getDstPort(), q.getDirection(),q.getDate(), q.getBytes()));
    	}
    	s.close();
    	return list;
    	
    }
    
    public static LinkedList<LogEntry>searchDB(String query){
    	//HibHelper.getSessionFactory().openSession();
    	
    	Session s = HibHelper.getSessionFactory().openSession();
    	List<Requests> r = (List<Requests>)s
    			.createQuery("from Requests where original_str like :term or data_str like :term2 order by id desc")
    			.setParameter("term", "%"+query+"%")
    			.setParameter("term2", "%"+query+"%")
    			.list();
    	LinkedList<LogEntry> list = new LinkedList<LogEntry>();
    	for(Requests q : r){
    		list.add(new LogEntry((long)q.getId(), q.getSrcIp(), q.getSrcPort(), q.getDstIp(), q.getDstPort(), q.getDirection(),q.getDate(), q.getBytes()));
    	}
    	s.close();
    	return list;
    	
    }
}