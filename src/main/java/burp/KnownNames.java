package burp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Container names this extension has written into notes, remembered with the project.
 *
 * <p>Notes now hold only the container's name, with no marker, so this is how the "Send to Repeater
 * (PhoenixBox)" action tells our notes from ones the user typed. A user note that happens to equal
 * a container name only earns an extra menu item.
 */
final class KnownNames {

    static final String KEY = "knownContainerNames";

    /** Oldest names are dropped past this, so a long-lived project cannot grow the set forever. */
    static final int MAX_NAMES = 500;

    private final ListenerManager.Store store;
    private final Set<String> names = new LinkedHashSet<>();

    KnownNames(ListenerManager.Store store) {
        this.store = store;
        load();
    }

    synchronized boolean contains(String name) {
        return name != null && names.contains(name);
    }

    synchronized void addAll(List<String> newNames) {
        boolean changed = false;
        for (String name : newNames) {
            if (name != null && !name.isEmpty() && !names.contains(name)) {
                names.add(name);
                changed = true;
            }
        }
        while (names.size() > MAX_NAMES) {
            names.remove(names.iterator().next());
            changed = true;
        }
        if (changed && store != null) {
            store.set(KEY, Json.write(new ArrayList<Object>(names)));
        }
    }

    private void load() {
        String stored = store == null ? null : store.get(KEY);
        if (stored == null) {
            return;
        }
        try {
            List<Object> values = Json.asArray(Json.parse(stored));
            if (values != null) {
                values.stream().filter(String.class::isInstance).map(String.class::cast).forEach(names::add);
            }
        } catch (IllegalArgumentException ignored) {
            // Start afresh rather than fail to load.
        }
    }
}
