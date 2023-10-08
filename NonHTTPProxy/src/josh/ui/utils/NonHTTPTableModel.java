package josh.ui.utils;

import java.text.SimpleDateFormat;
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
	private IHttpRequestResponse currentlyDisplayedItem;
	public JLabel label;

	public void initDB() {

		log = LogEntry.restoreDB();
	}

	public void removeRow(int row) {
		fireTableRowsDeleted(row, row);
	}

	public JLabel getLabel() {
		return this.label;
	}

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 10;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "#";
			case 1:
				return "Time";
			case 2:
				return "Proto";
			case 3:
				return "Direction - Annotation";
			case 4:
				return "Method";
			case 5:
				return "Src IP";
			case 6:
				return "Src Port";
			case 7:
				return "Dst IP";
			case 8:
				return "Dst Port";
			default:
				return "Bytes";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return Integer.class;
			case 6:
				return Integer.class;
			case 8:
				return Integer.class;
			case 9:
				return Integer.class;
			default:
				return String.class;
		}
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		try {
			// SimpleDateFormat sdf = new SimpleDateFormat("hh:mm:ss dd MMM yy");
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
			if (log.size() != 0) {
				LogEntry logEntry = log.get(rowIndex);

				switch (columnIndex) {
					case 0:
						return logEntry.Index;
					case 1:
						return sdf.format(logEntry.time);
					case 2:
						return logEntry.protocol;
					case 3:
						return logEntry.Direction;
					case 4:
						if (logEntry.Direction.contains("Repeater"))
							return "TCP Repeater";
						else if (logEntry.Direction.contains("Match"))
							return "Match";
						else if (logEntry.Direction.contains("mangle"))
							return "Mangle";
						else if (logEntry.Direction.contains("format"))
							return "Pre/Post Intercept";
						else if (logEntry.Direction.contains("**"))
							return "Intercept";
						else
							return "Normal";
					case 5:
						return logEntry.SrcIP;
					case 6:
						return logEntry.SrcPort;
					case 7:
						return logEntry.DstIP;
					case 8:
						return logEntry.DstPort;
					case 9:
						return logEntry.Bytes;

					default:
						return null;
				}
			} else {
				return null;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

	@Override
	public byte[] getRequest() {

		if (currentlyDisplayedItem == null)
			return new byte[] {};
		else
			return currentlyDisplayedItem.getRequest();

	}

	@Override
	public byte[] getResponse() {

		if (currentlyDisplayedItem == null)
			return new byte[] {};
		else
			return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService() {
		return currentlyDisplayedItem.getHttpService();
	}

}
