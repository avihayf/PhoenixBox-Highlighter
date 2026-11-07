package burp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Opens and closes the listeners this extension owns, and only those.
 *
 * <p>Every settings import makes Burp recreate all of its listeners, the user's own included, so
 * an import happens only when the owned set actually differs from what Burp has configured.
 */
final class ListenerManager {

    /** Burp's project settings, narrowed to what this class needs so tests can fake it. */
    interface ProjectOptions {
        String exportListeners();

        void importListeners(String json);
    }

    /** Where the owned set is remembered, so a crash cannot leave listeners behind for good. */
    interface Store {
        String get(String key);

        void set(String key, String value);
    }

    static final String OWNED_KEY = "ownedListeners";
    private static final String OWNER_KEY = "listenerOwner";
    private static final String COORDINATOR_KEY = "listenerCoordinator";

    private final ProjectOptions options;
    private final Store store;
    private final String owner = UUID.randomUUID().toString();
    private final Object coordinator;
    private Set<ListenerAddress> owned = new LinkedHashSet<>();

    ListenerManager(ProjectOptions options, Store store) {
        this.options = options;
        this.store = store;
        // Reloaded extensions have different class loaders. A project-specific
        // interned key provides the same monitor across both generations.
        synchronized ("phoenixbox.listener-coordinator-init".intern()) {
            String key = store.get(COORDINATOR_KEY);
            if (key == null) {
                key = UUID.randomUUID().toString();
                store.set(COORDINATOR_KEY, key);
            }
            coordinator = ("phoenixbox.listeners:" + key).intern();
        }
        // Reload can start before the old instance's queued cleanup finishes.
        // Only this generation may change the shared listeners and ownership record.
        synchronized (coordinator) {
            store.set(OWNER_KEY, owner);
        }
    }

    synchronized Set<ListenerAddress> owned() {
        return Set.copyOf(owned);
    }

    /** Burp's listeners minus ours: the ones allocation must steer clear of. */
    synchronized List<ListenerConfig.Entry> userListeners() {
        List<ListenerConfig.Entry> result = new ArrayList<>();
        for (ListenerConfig.Entry entry : ListenerConfig.parse(options.exportListeners())) {
            if (owned.stream().noneMatch(entry::isExactly)) {
                result.add(entry);
            }
        }
        return result;
    }

    /**
     * Makes the owned listeners exactly {@code desired}. Also re-adds an owned listener the user
     * deleted by hand, since this compares against Burp's live configuration rather than trusting
     * our own record.
     *
     * @return the addresses newly opened by this call.
     */
    synchronized Set<ListenerAddress> apply(Set<ListenerAddress> desired) {
        synchronized (coordinator) {
            return applyOwned(desired);
        }
    }

    private Set<ListenerAddress> applyOwned(Set<ListenerAddress> desired) {
        requireOwnership();
        List<ListenerConfig.Entry> configured = ListenerConfig.parse(options.exportListeners());

        Set<ListenerAddress> remove = new LinkedHashSet<>();
        for (ListenerAddress address : owned) {
            if (!desired.contains(address) && configured.stream().anyMatch(e -> e.isExactly(address))) {
                remove.add(address);
            }
        }

        Set<ListenerAddress> add = new LinkedHashSet<>();
        for (ListenerAddress address : desired) {
            if (configured.stream().noneMatch(e -> e.isExactly(address))) {
                add.add(address);
            }
        }

        if (!remove.isEmpty() || !add.isEmpty()) {
            // Record the union before importing: if Burp dies mid-import, the next load still
            // knows every listener that may now exist.
            Set<ListenerAddress> union = new LinkedHashSet<>(owned);
            union.addAll(add);
            persist(union);

            String next = ListenerConfig.rewrite(options.exportListeners(), remove, add);
            requireOwnership();
            options.importListeners(next);
        }

        owned = new LinkedHashSet<>(desired);
        persist(owned);
        return add;
    }

    /** Removes listeners a previous run recorded but never closed, e.g. after a crash. */
    synchronized void removeLeftovers() {
        synchronized (coordinator) {
            requireOwnership();
            Set<ListenerAddress> recorded = readPersisted();
            if (recorded.isEmpty()) {
                return;
            }

            owned = recorded;
            applyOwned(Set.of());
        }
    }

    synchronized void removeAll() {
        synchronized (coordinator) {
            if (!owner.equals(store.get(OWNER_KEY))) {
                owned = new LinkedHashSet<>();
                return;
            }
            applyOwned(Set.of());
        }
    }

    private void persist(Set<ListenerAddress> addresses) {
        requireOwnership();
        List<Object> values = new ArrayList<>();
        addresses.forEach(address -> values.add(address.toString()));
        store.set(OWNED_KEY, Json.write(values));
    }

    private void requireOwnership() {
        if (!owner.equals(store.get(OWNER_KEY))) {
            throw new IllegalStateException("listener ownership transferred to another Highlighter instance");
        }
    }

    private Set<ListenerAddress> readPersisted() {
        Set<ListenerAddress> result = new LinkedHashSet<>();
        String stored = store.get(OWNED_KEY);
        if (stored == null) {
            return result;
        }

        try {
            List<Object> values = Json.asArray(Json.parse(stored));
            if (values != null) {
                for (Object value : values) {
                    ListenerAddress address = value instanceof String ? ListenerAddress.tryParse((String) value) : null;
                    if (address != null) {
                        result.add(address);
                    }
                }
            }
        } catch (IllegalArgumentException ignored) {
            // A corrupt record: nothing we can safely remove.
        }
        return result;
    }
}
