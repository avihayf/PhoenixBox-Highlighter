package burp;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.function.Supplier;

/**
 * The "PhoenixBox" tab in Burp: the pairing string to copy into PhoenixBox, and which listener each
 * marked container is on. Read-only apart from copying and replacing the token.
 */
final class HighlighterTab extends JPanel {

    private final JTextField pairingField = new JTextField();
    private final JLabel statusLabel = new JLabel();
    private final RowsModel rowsModel = new RowsModel();
    private final Supplier<String> pairingString;
    private final Supplier<String> controlStatus;
    private final SyncService sync;
    private final Timer timer;

    HighlighterTab(Supplier<String> pairingString, Supplier<String> controlStatus, Runnable regenerateToken,
                   SyncService sync) {
        super(new BorderLayout(0, 8));
        this.pairingString = pairingString;
        this.controlStatus = controlStatus;
        this.sync = sync;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("PhoenixBox Highlighter v" + ContainerHighlighter.VERSION);
        title.setFont(title.getFont().deriveFont(title.getFont().getSize2D() + 3f));
        top.add(left(title));
        top.add(Box.createVerticalStrut(8));
        top.add(left(new JLabel("Pairing string. Paste it into PhoenixBox → Highlighter → Pair. "
                + "Treat it like a password.")));

        pairingField.setEditable(false);
        pairingField.setColumns(60);
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(pairingField.getText()), null));
        JButton regenerate = new JButton("New token");
        regenerate.setToolTipText("Replaces the token. PhoenixBox must be paired again.");
        regenerate.addActionListener(e -> {
            regenerateToken.run();
            refresh();
        });

        JPanel pairingRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        pairingRow.add(pairingField);
        pairingRow.add(copy);
        pairingRow.add(regenerate);
        top.add(left(pairingRow));
        top.add(Box.createVerticalStrut(6));
        top.add(left(statusLabel));

        add(top, BorderLayout.NORTH);

        JTable table = new JTable(rowsModel);
        table.setFillsViewportHeight(true);
        add(new JScrollPane(table), BorderLayout.CENTER);

        refresh();
        timer = new Timer(2000, e -> refresh());
        timer.start();
    }

    void stop() {
        timer.stop();
    }

    private void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }

        pairingField.setText(pairingString.get());
        long last = sync.lastSync();
        String seen = last < 0 ? "not connected" : "last sync " + ((System.currentTimeMillis() - last) / 1000) + "s ago";
        statusLabel.setText(controlStatus.get() + " · " + seen + " · " + sync.listenerCount() + " container listener(s)");
        rowsModel.setRows(sync.rows());
    }

    private static JPanel left(java.awt.Component component) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.add(component);
        return row;
    }

    private static final class RowsModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"Container", "Colour", "Listener", "Status"};
        private List<SyncService.Row> rows = List.of();

        void setRows(List<SyncService.Row> next) {
            if (!next.equals(rows)) {
                rows = next;
                fireTableDataChanged();
            }
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            SyncService.Row row = rows.get(rowIndex);
            switch (columnIndex) {
                case 0: return row.name();
                case 1: return row.color() == null ? "(none)" : row.color();
                case 2: return row.address() == null ? "" : row.address();
                default:
                    if (row.error() != null) {
                        return row.error();
                    }
                    return row.adopted() ? "using your listener" : "listening";
            }
        }
    }
}
