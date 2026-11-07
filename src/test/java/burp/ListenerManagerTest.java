package burp;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.ListenerConfigTest.USER_8080;
import static burp.ListenerConfigTest.at;
import static burp.ListenerConfigTest.export;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ListenerManagerTest {

    /** Stands in for Burp's project settings: remembers what was imported and counts imports. */
    static class FakeOptions implements ListenerManager.ProjectOptions {
        String json;
        int imports;

        FakeOptions(String json) {
            this.json = json;
        }

        @Override
        public String exportListeners() {
            return json;
        }

        @Override
        public void importListeners(String next) {
            json = next;
            imports++;
        }

        List<ListenerConfig.Entry> entries() {
            return ListenerConfig.parse(json);
        }

        boolean has(String address) {
            return entries().stream().anyMatch(e -> e.isExactly(at(address)));
        }
    }

    static final class MapStore implements ListenerManager.Store {
        final Map<String, String> values = new HashMap<>();

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public void set(String key, String value) {
            values.put(key, value);
        }
    }

    private final FakeOptions options = new FakeOptions(export(USER_8080));
    private final MapStore store = new MapStore();
    private final ListenerManager manager = new ListenerManager(options, store);

    @Test
    void replacementWaitsForAnAlreadyStartedCleanupImport() throws Exception {
        CountDownLatch importing = new CountDownLatch(1);
        CountDownLatch resume = new CountDownLatch(1);
        CountDownLatch replacing = new CountDownLatch(1);
        AtomicBoolean gate = new AtomicBoolean();
        FakeOptions blocked = new FakeOptions(export(USER_8080)) {
            @Override
            public void importListeners(String next) {
                if (gate.compareAndSet(true, false)) {
                    importing.countDown();
                    try {
                        if (!resume.await(3, TimeUnit.SECONDS)) throw new AssertionError("import gate timed out");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(e);
                    }
                }
                super.importListeners(next);
            }
        };
        ListenerManager previous = new ListenerManager(blocked, store);
        previous.apply(Set.of(at("127.0.0.1:18080")));
        gate.set(true);
        var workers = Executors.newFixedThreadPool(2);
        try {
            var cleanup = workers.submit(previous::removeAll);
            assertTrue(importing.await(3, TimeUnit.SECONDS));
            var startup = workers.submit(() -> {
                replacing.countDown();
                ListenerManager replacement = new ListenerManager(blocked, store);
                replacement.removeLeftovers();
                replacement.apply(Set.of(at("127.0.0.1:18080")));
            });
            try {
                assertTrue(replacing.await(3, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> startup.get(150, TimeUnit.MILLISECONDS));
            } finally {
                resume.countDown();
            }
            cleanup.get(3, TimeUnit.SECONDS);
            startup.get(3, TimeUnit.SECONDS);
            assertTrue(blocked.has("127.0.0.1:18080"));
            assertEquals("[\"127.0.0.1:18080\"]", store.get(ListenerManager.OWNED_KEY));
        } finally {
            resume.countDown();
            workers.shutdownNow();
        }
    }

    @Test
    void anOldInstancesDelayedCleanupCannotRemoveItsReplacementsListeners() {
        manager.apply(Set.of(at("127.0.0.1:18080")));
        ListenerManager replacement = new ListenerManager(options, store);
        replacement.removeLeftovers();
        replacement.apply(Set.of(at("127.0.0.1:18080")));

        manager.removeAll();

        assertTrue(options.has("127.0.0.1:18080"));
        assertEquals("[\"127.0.0.1:18080\"]", store.get(ListenerManager.OWNED_KEY));
        replacement.removeAll();
        assertEquals(1, options.entries().size());
        assertTrue(options.has("127.0.0.1:8080"));
    }

    @Test
    void opensAndClosesOnlyItsOwnListeners() {
        Set<ListenerAddress> opened = manager.apply(Set.of(at("127.0.0.1:18080"), at("127.0.0.1:18081")));

        assertEquals(Set.of(at("127.0.0.1:18080"), at("127.0.0.1:18081")), opened);
        assertTrue(options.has("127.0.0.1:18080") && options.has("127.0.0.1:18081") && options.has("127.0.0.1:8080"));

        manager.apply(Set.of(at("127.0.0.1:18081")));
        assertEquals(2, options.entries().size());
        assertTrue(options.has("127.0.0.1:8080") && options.has("127.0.0.1:18081"));

        manager.removeAll();
        assertEquals(1, options.entries().size());
        assertTrue(options.has("127.0.0.1:8080"));
    }

    @Test
    void doesNotImportWhenNothingChanged() {
        // Every import makes Burp restart all listeners, the user's included.
        manager.apply(Set.of(at("127.0.0.1:18080")));
        manager.apply(Set.of(at("127.0.0.1:18080")));
        manager.apply(Set.of(at("127.0.0.1:18080")));

        assertEquals(1, options.imports);
    }

    @Test
    void reopensAListenerTheUserDeletedByHand() {
        manager.apply(Set.of(at("127.0.0.1:18080")));
        options.json = export(USER_8080);

        Set<ListenerAddress> opened = manager.apply(Set.of(at("127.0.0.1:18080")));

        assertEquals(Set.of(at("127.0.0.1:18080")), opened);
        assertTrue(options.has("127.0.0.1:18080"));
    }

    @Test
    void excludesItsOwnListenersFromTheUsersList() {
        manager.apply(Set.of(at("127.0.0.1:18080")));

        List<ListenerConfig.Entry> user = manager.userListeners();
        assertEquals(1, user.size());
        assertEquals(8080, user.get(0).port());
    }

    @Test
    void removesLeftoversRecordedByAPreviousRunThatCrashed() {
        manager.apply(Set.of(at("127.0.0.1:18080"), at("192.168.10.2:18081")));

        // Burp restarts with the same project: a fresh manager, same settings and store.
        ListenerManager afterCrash = new ListenerManager(options, store);
        afterCrash.removeLeftovers();

        assertEquals(1, options.entries().size());
        assertTrue(options.has("127.0.0.1:8080"));
        assertTrue(afterCrash.owned().isEmpty());
    }

    @Test
    void recordsNewListenersBeforeImportingSoACrashMidImportLeavesNoOrphans() {
        ListenerManager.ProjectOptions crashing = new ListenerManager.ProjectOptions() {
            @Override
            public String exportListeners() {
                return export(USER_8080);
            }

            @Override
            public void importListeners(String json) {
                throw new IllegalStateException("Burp died");
            }
        };
        ListenerManager doomed = new ListenerManager(crashing, store);

        try {
            doomed.apply(Set.of(at("127.0.0.1:18080")));
        } catch (IllegalStateException expected) {
            // As if Burp went down during the import.
        }

        assertTrue(store.get(ListenerManager.OWNED_KEY).contains("127.0.0.1:18080"));
    }
}
