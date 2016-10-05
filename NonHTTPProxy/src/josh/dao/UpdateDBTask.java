package josh.dao;

import java.awt.Color;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.TimerTask;

import javax.swing.JTabbedPane;
import javax.swing.JTextField;

import org.hibernate.Session;

import jiconfont.icons.FontAwesome;
import jiconfont.swing.IconFontSwing;
import josh.ui.NonHttpUI;
import josh.ui.utils.LogEntry;
import josh.ui.utils.NonHTTPTableModel;

public class UpdateDBTask extends TimerTask{
	
	private Queue<LogEntry> queue;
	private NonHTTPTableModel ntbm;
	private JTextField searchTerm;
	private Session session;
	private JTabbedPane tabs;
	private Color NopeGreen =  new Color(0x2e,0x7d,0x32); //135, 211, 124);
	private Color NopeRed = new Color(214, 69, 65);
	private Color NopePurple = new Color(142, 68, 173); 
	private Color NopeBlue = new Color(65, 131, 215);
	private Color NopeOrange = new Color(249, 191, 59);
	
	public UpdateDBTask(Queue<LogEntry> queue, NonHTTPTableModel ntbm, JTextField searchTerm, JTabbedPane tabs){
		this.queue = queue;
		this.ntbm = ntbm;
		this.searchTerm = searchTerm;
		session = HibHelper.getSessionFactory().openSession();
		this.tabs = tabs;
		
		
	}
	

	@Override
	public void run() {
		try{
			//System.out.println("Working on Queue");
			
			if(queue.peek() == null)
				return;
			tabs.setIconAt(1,IconFontSwing.buildIcon(FontAwesome.DOWNLOAD,20, NopeRed));
			LogEntry le;
			List<LogEntry> updated = new ArrayList<LogEntry>();
			session.getTransaction().begin();
			while((le = queue.poll())!= null){
				Requests dao = new Requests(0, le.requestResponse, le.original, le.SrcIP, le.SrcPort, le.DstIP, le.DstPort, le.Direction, le.time.getTime(), le.Bytes);
				session.saveOrUpdate(dao);
				le.Index =(long)dao.getId();
				updated.add(le);
			}
			tabs.setIconAt(1,IconFontSwing.buildIcon(FontAwesome.DOWNLOAD,20, NopePurple));
			session.getTransaction().commit();
			for(LogEntry log : updated){
				if(searchTerm.getText().equals("") || le.canAdd(searchTerm.getText())){
					ntbm.log.addFirst(log);
					ntbm.fireTableRowsInserted(0, 0);
				}
			}
			tabs.setIconAt(1,IconFontSwing.buildIcon(FontAwesome.HISTORY,20, NopeOrange));
			
			//System.out.println("Finished with Queue");
		}catch(Exception ex){
			ex.printStackTrace();
		}
		
	}

	public void run3() {
		try{
			System.out.println("Working on Queue");
			 Connection c = null;
			 PreparedStatement stmt = null;
			    try {
			      Class.forName("org.sqlite.JDBC");
			      c = DriverManager.getConnection("jdbc:sqlite:C:/Users/Josh/.NopeProxy/requests.sqlite");
			    } catch ( Exception e ) {
			      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
			      System.exit(0);
			    }
			    System.out.println("Opened database successfully");
			    
			
			////LogEntry db = new LogEntry();
			//db.init();
			LogEntry le;
			//session.getTransaction().begin();
			String sql = "insert into requests (data, original,srcip,srcport,dstip,dstport,direction, date, bytes) "
                                       + "values ( ?,     ?,     ?   ,  ?    , ?   ,  ?  ,    ?    ,   ? ,   ?  )";
			while((le = queue.poll())!= null){
				
				stmt = c.prepareStatement(sql);
				stmt.setBytes(1, le.requestResponse);
				stmt.setBytes(2, le.original);
				stmt.setString(3, le.SrcIP);
				stmt.setInt(4, le.SrcPort);
				stmt.setString(5,le.DstIP);
				stmt.setInt(6, le.DstPort);
				stmt.setString(7, le.Direction);
				stmt.setDate(8, new java.sql.Date(le.time.getTime()));
				stmt.setInt(9, le.Bytes);
				stmt.executeUpdate();
				stmt.close();
				///Requests dao = new Requests(0, le.requestResponse, le.original, le.SrcIP, le.SrcPort, le.DstIP, le.DstPort, le.Direction, le.time.getTime(), le.Bytes);
				//session.save(dao);
				//le.Index =(long)dao.getId();
				//le.save();
				//le.saveCommitDeferred(le);
				//if(searchTerm.getText().equals("") || le.canAdd(searchTerm.getText())){
					ntbm.log.addFirst(le);
					ntbm.fireTableRowsInserted(0, 0);
				//}
			}
			//session.getTransaction().commit();
			//session.close();
			//db.commit();
			c.close();
			System.out.println("Finished with Queue");
		}catch(Exception ex){
			ex.printStackTrace();
		}
		
	}
	
	public void run2() {
		System.out.println("Working on Queue");
		LogEntry db = new LogEntry();
		db.init();
		LogEntry le;
		List<LogEntry> logs = new ArrayList<LogEntry>();
		while((le = queue.poll())!= null){
			logs.add(le);
		}
		for(LogEntry log : logs){
			db.saveCommitDeferred(log);
		}
		db.commit();
		for(LogEntry log : logs){
			//if(log.canAdd(searchTerm.getText())){
				ntbm.log.addFirst(log);
				ntbm.fireTableRowsInserted(0, 0);
			//}
		}
		//db.commit();
		System.out.println("Finished with Queue");
		
	}


}
