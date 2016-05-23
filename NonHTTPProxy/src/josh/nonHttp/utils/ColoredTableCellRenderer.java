package josh.nonHttp.utils;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

@SuppressWarnings("serial")
public class ColoredTableCellRenderer extends DefaultTableCellRenderer{
	
	public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focused, int row, int column)
	{
	    setEnabled(table == null || table.isEnabled()); // see question above
	
	    if ((row % 2) == 0)
	        setBackground(Color.green);
	    else
	        setBackground(Color.lightGray);
	
	    super.getTableCellRendererComponent(table, value, selected, focused, row, column);
	
	    return this;
	}

}
