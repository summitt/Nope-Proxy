package josh.ui.utils;

import java.util.LinkedList;

public class Support {

    public static void updateTable(NonHTTPTableModel model, String searchText, boolean showHighlighted) {
        searchTable(model, searchText, showHighlighted);
        /*if (!searchText.equals("")) {
            searchTable(model, searchText, showHighlighted);
        } else {
            resetTable(model);
        }*/
    }

    private static void resetTable(NonHTTPTableModel model) {
        int rowCount = model.getRowCount();
        if (rowCount > 0) {
            for (int i = rowCount - 1; i >= 0; i--) {
                model.log.remove(i);
            }
        }
        LinkedList<LogEntry> list = LogEntry.restoreDB();
        for (LogEntry le : list) {
            model.log.add(le);

        }
        model.fireTableDataChanged();

    }

    private static void searchTable(final NonHTTPTableModel model, final String searchText, boolean showHighlighted) {
        int rowCount = model.getRowCount();
        if (rowCount > 0) {
            for (int i = rowCount - 1; i >= 0; i--) {
                model.log.remove(i);
            }
        }
        LinkedList<LogEntry> list = LogEntry.searchDB(searchText.trim(), showHighlighted);
        for (LogEntry le : list) {
            model.log.add(le);
        }
        model.fireTableDataChanged();

    }

}
