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
 * The "PhoenixBox" tab in Burp: the mode, pairing requests to approve, the PhoenixBox profiles
 * already paired, and which listener each marked container is on.
 *
 * <p>Everything here runs on Burp's UI thread and only reads lock-free snapshots from
 * {@link SyncService} and {@link PairingService}: a sync holds its lock while Burp applies listener
 * changes on this same thread, so waiting on that lock here would freeze Burp.
 */
final class HighlighterTab extends JPanel {

    private final JLabel modeLabel = new JLabel();
    private final JLabel statusLabel = new JLabel();
    private final JPanel requestBanner = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    private final JLabel requestLabel = new JLabel();
    private final JTextField pairingField = new JTextField();
    private final RowsModel rowsModel = new RowsModel();
    private final ClientsModel clientsModel = new ClientsModel();
    private final Supplier<String> pairingString;
    private final Supplier<String> controlStatus;
    private final SyncService sync;
    private final PairingService pairing;
    private final Timer timer;

    /**
     * @param revokeAll unpairs everyone and replaces the manual pairing string.
     * @param afterRevoke run after any revocation; must hand its work off this (UI) thread.
     */
    HighlighterTab(Supplier<String> pairingString, Supplier<String> controlStatus, Runnable revokeAll,
                   Runnable afterRevoke, SyncService sync, PairingService pairing) {
        super(new BorderLayout(0, 8));
        this.pairingString = pairingString;
        this.controlStatus = controlStatus;
        this.sync = sync;
        this.pairing = pairing;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("PhoenixBox Highlighter v" + ContainerHighlighter.VERSION);
        title.setFont(title.getFont().deriveFont(title.getFont().getSize2D() + 3f));
        top.add(left(title));
        top.add(Box.createVerticalStrut(6));
        top.add(left(modeLabel));
        top.add(left(statusLabel));
        top.add(Box.createVerticalStrut(8));

        JButton allow = new JButton("Allow");
        JButton deny = new JButton("Deny");
        allow.addActionListener(e -> answer(true));
        deny.addActionListener(e -> answer(false));
        requestBanner.add(requestLabel);
        requestBanner.add(allow);
        requestBanner.add(deny);
        requestBanner.setVisible(false);
        top.add(left(requestBanner));

        top.add(Box.createVerticalStrut(8));
        top.add(left(new JLabel("Paired PhoenixBox profiles:")));
        JTable clients = new JTable(clientsModel);
        clients.setFillsViewportHeight(true);
        JScrollPane clientsPane = new JScrollPane(clients);
        clientsPane.setPreferredSize(new java.awt.Dimension(640, 90));
        JButton revoke = new JButton("Revoke selected");
        revoke.addActionListener(e -> {
            int row = clients.getSelectedRow();
            if (row >= 0) {
                pairing.revoke(clientsModel.idAt(row));
                afterRevoke.run();
                refresh();
            }
        });
        JButton revokeAllButton = new JButton("Revoke all");
        revokeAllButton.setToolTipText("Unpairs every PhoenixBox and replaces the manual pairing string.");
        revokeAllButton.addActionListener(e -> {
            revokeAll.run();
            afterRevoke.run();
            refresh();
        });
        top.add(left(clientsPane));
        JPanel clientButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        clientButtons.add(revoke);
        clientButtons.add(revokeAllButton);
        top.add(left(clientButtons));

        top.add(Box.createVerticalStrut(8));
        top.add(left(new JLabel("Manual pairing, only if PhoenixBox cannot find Burp. Treat it like a password.")));
        pairingField.setEditable(false);
        pairingField.setColumns(60);
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(pairingField.getText()), null));
        JPanel pairingRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        pairingRow.add(pairingField);
        pairingRow.add(copy);
        top.add(left(pairingRow));

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

    /**
     * A PhoenixBox wants to pair: show the Allow / Deny banner at the top of this tab. Called from
     * the control server's thread, which must not wait, so the refresh is only scheduled.
     */
    void promptForPairing(PairingService.Pending request) {
        SwingUtilities.invokeLater(this::refresh);
    }

    private void answer(boolean allow) {
        PairingService.Pending request = pairing.pending();
        if (request != null) {
            pairing.decide(request.id(), allow);
        }
        refresh();
    }

    private void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }

        modeLabel.setText(sync.isPaired()
                ? "Mode: paired — highlighting by listener, no headers."
                : "Mode: not paired — legacy colour header (coloured, stripped).");
        long last = sync.lastSync();
        String seen = last < 0 ? "no PhoenixBox syncing" : "last sync " + ((System.currentTimeMillis() - last) / 1000) + "s ago";
        statusLabel.setText(controlStatus.get() + " · " + seen + " · " + sync.listenerCount() + " container listener(s)");

        PairingService.Pending request = pairing.pending();
        if (request == null) {
            requestBanner.setVisible(false);
        } else {
            requestLabel.setText("Pairing request from " + request.label() + " (" + request.origin()
                    + ", client " + shortId(request.id()) + "). It will be able to open proxy listeners:");
            requestBanner.setVisible(true);
        }

        pairingField.setText(pairingString.get());
        clientsModel.setClients(pairing.clients());
        rowsModel.setRows(sync.rows());
    }

    private static String shortId(String id) {
        return id.length() <= 8 ? id : "…" + id.substring(id.length() - 6);
    }

    private static JPanel left(java.awt.Component component) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.add(component);
        return row;
    }

    private static final class ClientsModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"PhoenixBox", "Extension", "Client"};
        private List<PairingService.Client> clients = List.of();

        void setClients(List<PairingService.Client> next) {
            if (!next.equals(clients)) {
                clients = next;
                fireTableDataChanged();
            }
        }

        String idAt(int row) {
            return clients.get(row).id();
        }

        @Override
        public int getRowCount() {
            return clients.size();
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
            PairingService.Client client = clients.get(rowIndex);
            switch (columnIndex) {
                case 0: return client.label();
                case 1: return client.origin();
                default: return shortId(client.id());
            }
        }
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
