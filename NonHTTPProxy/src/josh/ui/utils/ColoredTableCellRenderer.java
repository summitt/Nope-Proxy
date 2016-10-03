package josh.ui.utils;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

@SuppressWarnings("serial")
public class ColoredTableCellRenderer extends DefaultTableCellRenderer{
	
	public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focused, int row, int column)
	{
	   if(selected){
		   if (table.isCellSelected(row, column))
			    setForeground(Color.red);
			else if (table.isRowSelected(row))
			    setForeground(Color.green);
			else if (table.isColumnSelected(column))
			    setForeground(Color.blue);
			else
			    setForeground(Color.black);
	   }
	
	    super.getTableCellRendererComponent(table, value, selected, focused, row, column);
	
	    return this;
	}

}
