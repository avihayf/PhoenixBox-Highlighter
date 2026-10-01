package burp;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static burp.ListenerConfigTest.USER_8080;
import static burp.ListenerConfigTest.at;
import static burp.ListenerConfigTest.export;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SyncServiceTest {

    private final ListenerManagerTest.FakeOptions options = new ListenerManagerTest.FakeOptions(export(USER_8080));
    private final ListenerManagerTest.MapStore store = new ListenerManagerTest.MapStore();
    private final ContainerRegistry registry = new ContainerRegistry();
    private final KnownNames knownNames = new KnownNames(store);
    private final AtomicLong now = new AtomicLong(1_000_000);
    private final Set<ListenerAddress> dead = new HashSet<>();

    private final AddressProbe probe = new AddressProbe() {
        @Override
        public Result probe(ListenerAddress address) {
            return Result.FREE;
        }

        @Override
        public boolean answers(ListenerAddress address) {
            return !dead.contains(address);
        }
    };

    private final SyncService sync = new SyncService(new ListenerManager(options, store), registry, knownNames, probe,
            at("127.0.0.1:8079"), now::get);

    private static Map<String, Object> body(String containersJson) {
        return Json.asObject(Json.parse("{\"protocol\":1,\"preset\":{\"host\":\"127.0.0.1\",\"port\":8080},"
                + "\"containers\":" + containersJson + "}"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> assignment(Map<String, Object> response, String id) {
        return (Map<String, Object>) ((Map<String, Object>) response.get("assignments")).get(id);
    }

    @Test
    void opensAListenerPerMarkedContainerAndAttributesItsTraffic() {
        Map<String, Object> response = sync.sync(body(
                "[{\"id\":\"firefox-container-1\",\"name\":\"Work\",\"color\":\"red\"},"
                        + "{\"id\":\"firefox-container-2\",\"name\":\"Admin\",\"color\":\"blue\"}]"));

        assertEquals("ok", assignment(response, "firefox-container-1").get("status"));
        assertEquals("127.0.0.1:18080", assignment(response, "firefox-container-1").get("address"));
        assertEquals("127.0.0.1:18081", assignment(response, "firefox-container-2").get("address"));
        assertEquals(ContainerHighlighter.VERSION, response.get("jar"));

        assertEquals("Work", registry.lookup("127.0.0.1:18080").name());
        assertEquals("blue", registry.lookup("127.0.0.1:18081").color());
        assertNull(registry.lookup("127.0.0.1:8080"));
        assertTrue(knownNames.contains("Work"));
        assertEquals(3, options.entries().size());
    }

    @Test
    void unmarkingAContainerClosesItsListener() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"},{\"id\":\"b\",\"name\":\"B\",\"color\":\"red\"}]"));
        sync.sync(body("[{\"id\":\"b\",\"name\":\"B\",\"color\":\"red\"}]"));

        assertEquals(2, options.entries().size());
        assertNull(registry.lookup("127.0.0.1:18080"));
        assertEquals("B", registry.lookup("127.0.0.1:18081").name());
    }

    @Test
    void aRenameUpdatesAttributionWithoutTouchingBurpsSettings() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"Old\",\"color\":\"red\"}]"));
        int imports = options.imports;

        sync.sync(body("[{\"id\":\"a\",\"name\":\"New\",\"color\":\"green\"}]"));

        assertEquals(imports, options.imports);
        assertEquals("New", registry.lookup("127.0.0.1:18080").name());
        assertEquals("green", registry.lookup("127.0.0.1:18080").color());
    }

    @Test
    void reportsAListenerBurpDidNotBringUpAndDoesNotAttributeIt() {
        dead.add(at("127.0.0.1:18080"));

        Map<String, Object> response = sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]"));

        assertEquals("error", assignment(response, "a").get("status"));
        assertNull(assignment(response, "a").get("address"));
        assertNull(registry.lookup("127.0.0.1:18080"));
    }

    @Test
    void cleansNamesAndDropsUnknownColours() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"  Bad\\r\\nName\\u0000 \",\"color\":\"chartreuse\"},"
                + "{\"id\":\"b\",\"name\":\"" + "x".repeat(100) + "\",\"color\":null}]"));

        assertEquals("BadName", registry.lookup("127.0.0.1:18080").name());
        assertNull(registry.lookup("127.0.0.1:18080").color());
        assertEquals(64, registry.lookup("127.0.0.1:18081").name().length());
    }

    @Test
    void rejectsMalformedSyncs() {
        List<Map<String, Object>> bad = List.of(
                Json.asObject(Json.parse("{\"protocol\":2,\"preset\":{\"host\":\"127.0.0.1\",\"port\":8080},\"containers\":[]}")),
                Json.asObject(Json.parse("{\"protocol\":1,\"containers\":[]}")),
                Json.asObject(Json.parse("{\"protocol\":1,\"preset\":{\"host\":\"127.0.0.1\",\"port\":0},\"containers\":[]}")),
                body("{}"),
                body("[{\"name\":\"no id\"}]"),
                body("[{\"id\":\"a\"},{\"id\":\"a\"}]"),
                body("[{\"id\":\"a\",\"pin\":\"not an address\"}]"));

        for (Map<String, Object> request : bad) {
            assertThrows(SyncService.BadSync.class, () -> sync.sync(request), String.valueOf(request));
        }
    }

    @Test
    void closesEverythingWhenPhoenixBoxGoesQuietForTheWholeLease() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]"));

        now.addAndGet(SyncService.LEASE_MS - 1);
        sync.expireIfIdle();
        assertEquals(2, options.entries().size());

        now.addAndGet(2);
        sync.expireIfIdle();
        assertEquals(1, options.entries().size());
        assertNull(registry.lookup("127.0.0.1:18080"));
        assertEquals(-1, sync.lastSync());
    }

    @Test
    void readersNeverWaitForASyncThatIsInsideBurp() throws Exception {
        // Burp applies a listener change by waiting on its UI thread, and the Burp tab reads these
        // accessors on that same thread. If they waited for the sync, Burp's UI would deadlock.
        java.util.concurrent.CountDownLatch insideImport = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        ListenerManagerTest.FakeOptions blocking = new ListenerManagerTest.FakeOptions(export(USER_8080)) {
            @Override
            public void importListeners(String next) {
                insideImport.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                super.importListeners(next);
            }
        };
        SyncService blockingSync = new SyncService(new ListenerManager(blocking, store), registry, knownNames, probe,
                at("127.0.0.1:8079"), now::get);

        Thread syncing = new Thread(() -> blockingSync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]")));
        syncing.start();
        assertTrue(insideImport.await(5, java.util.concurrent.TimeUnit.SECONDS));

        java.util.concurrent.FutureTask<Boolean> read = new java.util.concurrent.FutureTask<>(() -> {
            blockingSync.rows();
            blockingSync.lastSync();
            blockingSync.listenerCount();
            return true;
        });
        new Thread(read).start();
        try {
            assertTrue(read.get(2, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            release.countDown();
            syncing.join(5000);
        }
    }

    @Test
    void isPairedWhileSyncingAndNotAfterReleaseOrTheLease() {
        assertFalse(sync.isPaired());

        sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]"));
        assertTrue(sync.isPaired());

        now.addAndGet(SyncService.LEASE_MS + 1);
        sync.expireIfIdle();
        assertFalse(sync.isPaired());
    }

    @Test
    void aReleaseLeavesPairedModeAndClosesListenersAtOnce() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]"));
        assertEquals(2, options.entries().size());

        Map<String, Object> released = sync.sync(Json.asObject(Json.parse("{\"protocol\":1,\"release\":true}")));

        assertFalse(sync.isPaired());
        assertEquals(1, options.entries().size());
        assertNull(registry.lookup("127.0.0.1:18080"));
        assertTrue(((Map<?, ?>) released.get("assignments")).isEmpty());
    }

    @Test
    void anEmptySyncClosesEverything() {
        sync.sync(body("[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]"));
        sync.sync(body("[]"));

        assertEquals(1, options.entries().size());
        assertEquals(0, sync.listenerCount());
    }
}
