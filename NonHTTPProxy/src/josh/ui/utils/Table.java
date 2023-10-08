package josh.ui.utils;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import org.hibernate.Session;

import burp.IMessageEditor;
import jiconfont.icons.Elusive;
import jiconfont.swing.IconFontSwing;
import josh.dao.Requests;

@SuppressWarnings("serial")
public class Table extends JTable {

    public List<LogEntry> log = new ArrayList<LogEntry>();
    private IMessageEditor requestViewer;
    private IMessageEditor originalViewer;
    private byte[] currentlyDisplayedItem;
    private JLabel label;
    private TableModel tableModel;
    private Session session;
    public Long selectedIndex;
    public LinkedHashMap<String, Color> bgColors = new LinkedHashMap<String, Color>();
    public HashMap<String, Color> fgColors = new HashMap<String, Color>();

    public Table(TableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;
        this.setAutoCreateRowSorter(true);
        this.log = ((NonHTTPTableModel) tableModel).log;
        this.requestViewer = ((NonHTTPTableModel) tableModel).requestViewer;
        this.originalViewer = ((NonHTTPTableModel) tableModel).originalViewer;
        int alpha = 0x9F;
        bgColors.put("red", new Color(0xFF, 0x57, 0x33, alpha));
        fgColors.put("red", Color.WHITE);

        bgColors.put("orange", new Color(0xFF, 0xB2, 0x33, alpha));
        bgColors.put("yellow", new Color(0xFC, 0xFF, 0x33, alpha));
        bgColors.put("green", new Color(0x8D, 0xFF, 0x33, alpha));
        bgColors.put("cyan", new Color(0x33, 0xFF, 0xD7, alpha));

        bgColors.put("blue", new Color(0x33, 0x96, 0xFF, alpha));
        fgColors.put("blue", Color.WHITE);

        bgColors.put("purple", new Color(0x7D, 0x33, 0xFF, alpha));
        fgColors.put("purple", Color.WHITE);

        bgColors.put("clear", Color.white);
    }

    public void setColor(String color) {
        int[] rows = this.getSelectedRows();

        for (int row : rows) {
            int modelRow = this.convertRowIndexToModel(row);
            LogEntry logEntry = log.get(modelRow);
            ((NonHTTPTableModel) this.tableModel).removeRow(modelRow);

            logEntry.updateColor(color);
        }

    }

    public void deleteMultipleRows() {
        int row = this.getSelectedRow();

        while (row != -1) {
            int modelRow = this.convertRowIndexToModel(row);
            LogEntry logEntry = log.get(modelRow);
            ((NonHTTPTableModel) this.tableModel).removeRow(modelRow);
            logEntry.delete();
            log.remove(modelRow);
            row = this.getSelectedRow();
        }
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        // show the log entry for the selected row
        // System.out.println("Row is: " + row);

        int r = this.convertRowIndexToModel(row);

        LogEntry logEntry = log.get(r);
        Requests req = logEntry.getData(logEntry.Index);
        requestViewer.setMessage(req.getData() == null
                ? "Nope Proxy thinks you're requesting data too fast from Database. :( Try again in a sec ...."
                        .getBytes()
                : req.getData(), true);
        originalViewer.setMessage(req.getOriginal() == null
                ? "Nope Proxy thinks you're requesting data too fast from Database. :( Try again in a sec ...."
                        .getBytes()
                : req.getOriginal(), true);

        currentlyDisplayedItem = logEntry.requestResponse;
        this.selectedIndex = logEntry.Index;
        JLabel start = new JLabel("" + logEntry.Index + " - " + logEntry.Direction + " - " +
                logEntry.SrcIP + ":" + logEntry.SrcPort);
        JLabel arrow = new JLabel();
        arrow.setIcon(IconFontSwing.buildIcon(Elusive.ARROW_RIGHT, 16));
        JLabel end = new JLabel("" + logEntry.DstIP + ":" + logEntry.DstPort +
                " Size: " + logEntry.Bytes);

        ((NonHTTPTableModel) this.getModel()).getLabel().setText(
                "" + logEntry.Index + " - " + logEntry.Direction + " - " +
                        logEntry.SrcIP + ":" + logEntry.SrcPort + " " + (char) 0xBB + (char) 0xBB + " " + logEntry.DstIP
                        + ":" + logEntry.DstPort +
                        " Size: " + logEntry.Bytes);
        /*
         * ((NonHTTPTableModel)this.getModel()).getLabel().removeAll();
         * 
         * ((NonHTTPTableModel)this.getModel()).getLabel().setLayout(new
         * BoxLayout(((NonHTTPTableModel)this.getModel()).getLabel(),
         * BoxLayout.X_AXIS));
         * ((NonHTTPTableModel)this.getModel()).getLabel().add(start);
         * ((NonHTTPTableModel)this.getModel()).getLabel().add(arrow);
         * ((NonHTTPTableModel)this.getModel()).getLabel().add(end);
         * ((NonHTTPTableModel)this.getModel()).getLabel().setText("");
         * ((NonHTTPTableModel)this.getModel()).getLabel().
         */

        super.changeSelection(row, col, toggle, extend);
    }

    public Long getSelectedIndex() {
        return this.selectedIndex;
    }

    @Override
    public Component prepareRenderer(
            TableCellRenderer renderer, int row, int column) {
        Component c = super.prepareRenderer(renderer, row, column);
        try {
            super.isRowSelected(row);


            // c.setBackground(Color.cyan);
            /*
             * Border outside = new MatteBorder(0, 1, 0, 1, Color.gray);
             * Border inside = new EmptyBorder(0, 1, 0, 1);
             * Border highlight = new CompoundBorder(outside, inside);
             * JComponent jc = (JComponent)c;
             */
            if (log.size() == 0) {
                return c;
            }

            int r = this.convertRowIndexToModel(row);
            if (super.isRowSelected(row)) {
                c.setBackground(new Color(52, 73, 94));
            } else if (log.get(r).color != null || log.get(r).color != "") {
                c.setBackground(this.bgColors.get(log.get(r).color));
            } else if (log.get(r).Direction.contains("**")) {
                c.setBackground(new Color(0xf1, 0xc4, 0x0f));
            } else if (log.get(r).Direction.contains("Repeater")) {
                c.setBackground(new Color(0xF3, 0xFA, 0xB6));
                /*
                 * }else if(log.get(r).Direction.contains("Python")){
                 * //c.setBackground( new Color(0x2e,0xcc, 0x71));
                 * 
                 * c.setBackground( new Color(0xCB,0xE3,0x2D));
                 */
            } else if (log.get(r).Direction.contains("Match")) {
                c.setBackground(new Color(149, 165, 166));
            } else if ((row % 2) == 0) {
                // c.setBackground(Color.cyan);
                c.setBackground(new Color(0xec, 0xf0, 0xf1));
            } else
                c.setBackground(new Color(0xbd, 0xc3, 0xc7));

            if (log.get(r).Direction.contains("c2s")) {
                if (!super.isRowSelected(row))
                    c.setForeground(Color.blue);
                else
                    c.setForeground(Color.white);
            } else {
                if (!super.isRowSelected(row))
                    c.setForeground(new Color(192, 57, 43));
                else
                    c.setForeground(new Color(0xff, 0xe6, 0xe6));
                // c.setForeground(new Color(231, 76, 60));

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }

        return c;
    }

}