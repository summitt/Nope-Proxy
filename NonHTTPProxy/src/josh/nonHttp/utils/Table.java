package josh.nonHttp.utils;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import org.hibernate.Session;
import burp.IMessageEditor;
import josh.dao.Requests;

@SuppressWarnings("serial")
public class Table extends JTable
{
	
	public List<LogEntry> log = new ArrayList<LogEntry>();
	private IMessageEditor requestViewer;
	private IMessageEditor originalViewer;
	private byte[] currentlyDisplayedItem;
	private JLabel label;
	private TableModel tableModel;
	private Session session;
	
    public Table(TableModel tableModel)
    {
    	super(tableModel);
    	this.setAutoCreateRowSorter(true);
        this.log = ((NonHTTPTableModel)tableModel).log;
        this.requestViewer = ((NonHTTPTableModel)tableModel).requestViewer;
        this.originalViewer = ((NonHTTPTableModel)tableModel).originalViewer;
       
       
    }
    
    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        // show the log entry for the selected row
    	//System.out.println("Row is: " + row);
    	
    	int r = this.convertRowIndexToModel(row);
        LogEntry logEntry = log.get(r);
        Requests req = logEntry.getData(logEntry.Index);
        requestViewer.setMessage(req.getData(), true);
        originalViewer.setMessage(req.getOriginal(), true);
       
        currentlyDisplayedItem = logEntry.requestResponse;
        ((NonHTTPTableModel)this.getModel()).getLabel().setText(
        		""+logEntry.Index + " - " + logEntry.Direction + " - " +
        		logEntry.SrcIP + ":" + logEntry.SrcPort + " -> " + logEntry.DstIP + ":" + logEntry.DstPort +
        		" Size: " + logEntry.Bytes );
        
        
        super.changeSelection(row, col, toggle, extend);
    }   
    
  
    
    @Override
    public Component prepareRenderer(
            TableCellRenderer renderer, int row, int column)
        {
            Component c = super.prepareRenderer(renderer, row, column);
            //c.setBackground(Color.cyan);
            /*Border outside = new MatteBorder(0, 1, 0, 1, Color.gray);
			Border inside = new EmptyBorder(0, 1, 0, 1);
			Border highlight = new CompoundBorder(outside, inside);
            JComponent jc = (JComponent)c;*/
            int r = this.convertRowIndexToModel(row);
            if(log.get(r).Direction.contains("**")){
             	c.setBackground(Color.cyan);  
            }else if((row%2)==0){
            	//c.setBackground(Color.cyan);
            	c.setBackground(UIManager.getColor("Button.background"));
            }else
            	c.setBackground(UIManager.getColor("Button.highlight"));
           
            
           
            if(log.get(r).Direction.contains("c2s")){
            	c.setForeground(Color.blue);
            }else
            	c.setForeground(new Color(0xE4, 0x31, 0x17));
            

            return c;
        }
    
 
}