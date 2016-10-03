package josh.dao;

import java.util.Queue;
import java.util.TimerTask;

import javax.swing.JTextField;

import josh.ui.utils.LogEntry;
import josh.ui.utils.NonHTTPTableModel;

public class UpdateDBTask extends TimerTask{
	
	private Queue<LogEntry> queue;
	private NonHTTPTableModel ntbm;
	private JTextField searchTerm;
	
	public UpdateDBTask(Queue<LogEntry> queue, NonHTTPTableModel ntbm, JTextField searchTerm){
		this.queue = queue;
		this.ntbm = ntbm;
		this.searchTerm = searchTerm;
	}
	

	@Override
	public void run() {
		//System.out.println("Working on Queue");
		LogEntry le;
		while((le = queue.poll())!= null){
			le.save();
			if(le.canAdd(searchTerm.getText())){
				ntbm.log.addFirst(le);
				ntbm.fireTableRowsInserted(0, 0);
			}
		}
		//System.out.println("Finished with Queue");
		
	}

}
