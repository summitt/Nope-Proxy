package josh.nonHttp.utils;


import java.util.LinkedList;
import javax.swing.JLabel;
import javax.swing.table.AbstractTableModel;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

@SuppressWarnings("serial")
public class NonHTTPTableModel extends AbstractTableModel implements IMessageEditorController {

	public IMessageEditor requestViewer;
	public IMessageEditor originalViewer;
	
	public LinkedList<LogEntry> log = new LinkedList<LogEntry>();
	public IHttpRequestResponse currentlyDisplayedItem;
	public JLabel label;

	public void initDB(){
		
		log = LogEntry.restoreDB();
	}
	
	
	public JLabel getLabel(){
		return this.label;
	}


	@Override
	public int getRowCount()
	{
		return log.size();
	}

	@Override
	public int getColumnCount()
	{
		return 8;
	}

	@Override
	public String getColumnName(int columnIndex)
	{
		switch (columnIndex)
		{
		case 0:
			return "#";
		case 1:
			return "Time";
		case 2:
			return "Direction";
		case 3:
			return "Source IP";
		case 4:
			return "Source Port";
		case 5:
			return "Dst IP";
		case 6:
			return "Dst Port";
		default:
			return "Bytes";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex)
	{
		switch (columnIndex)
		{
			case 0: return Integer.class;
			case 4: return Integer.class;
			case 6: return Integer.class;
			case 7: return Integer.class;
			default: return String.class;
		}
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex)
	{
		if(log.size() != 0){
			LogEntry logEntry = log.get(rowIndex);
	
			switch (columnIndex)
			{
			case 0:
				return logEntry.Index;
			case 1:
				return logEntry.time.toString();
			case 2:
				return logEntry.Direction;
			case 3:
				return logEntry.SrcIP;
			case 4:
				return logEntry.SrcPort;
			case 5:
				return logEntry.DstIP;
			case 6:
				return logEntry.DstPort;
			case 7:
				return logEntry.Bytes;
			default: return null;
			}
		}else{
			return  null;
		}
	}



	@Override
	public byte[] getRequest()
	{
		if(currentlyDisplayedItem==null)
			return new byte[]{};
		else
			return currentlyDisplayedItem.getRequest();
		
	}

	@Override
	public byte[] getResponse()
	{
		if(currentlyDisplayedItem==null)
			return new byte[]{};
		else
			return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService()
	{
		return currentlyDisplayedItem.getHttpService();
	}

	
	

}
