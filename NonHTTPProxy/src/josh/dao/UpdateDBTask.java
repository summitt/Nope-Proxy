package josh.dao;

import java.util.Queue;
import java.util.TimerTask;

import josh.nonHttp.utils.LogEntry;
import josh.nonHttp.utils.NonHTTPTableModel;

public class UpdateDBTask extends TimerTask{
	
	private Queue<LogEntry> queue;
	private NonHTTPTableModel ntbm;
	
	public UpdateDBTask(Queue<LogEntry> queue, NonHTTPTableModel ntbm){
		this.queue = queue;
		this.ntbm = ntbm;
	}
	

	@Override
	public void run() {
		//System.out.println("Working on Queue");
		LogEntry le;
		while((le = queue.poll())!= null){
			le.save();
			ntbm.log.addFirst(le);
			ntbm.fireTableRowsInserted(0, 0);
		}
		//System.out.println("Finished with Queue");
		
	}

}
