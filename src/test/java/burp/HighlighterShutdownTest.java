package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static burp.ListenerConfigTest.USER_8080;
import static burp.ListenerConfigTest.export;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HighlighterShutdownTest {
    private static final Map<String, Object> BODY = Json.asObject(Json.parse(
            "{\"protocol\":1,\"preset\":{\"host\":\"127.0.0.1\",\"port\":8080},"
                    + "\"containers\":[{\"id\":\"a\",\"name\":\"Admin\"}]}"));

    @Test
    void anAllocatingSyncCannotReopenListenersAfterUnload() throws Exception {
        CountDownLatch allocating = new CountDownLatch(1);
        CountDownLatch resume = new CountDownLatch(1);
        AddressProbe probe = new AddressProbe() {
            public Result probe(ListenerAddress address) {
                allocating.countDown();
                await(resume);
                return Result.FREE;
            }
            public boolean answers(ListenerAddress address) { return true; }
        };
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (Running running = new Running(new ListenerManagerTest.FakeOptions(export(USER_8080)), probe)) {
            Future<?> request = worker.submit(() -> syncUntilStopped(running.sync));
            try {
                assertTrue(allocating.await(3, TimeUnit.SECONDS));
                running.unload();
            } finally {
                resume.countDown();
            }
            request.get(3, TimeUnit.SECONDS);
            running.awaitCleanup();
            assertEquals(0, running.options.imports);
            assertEquals(0, running.highlighter.registry().size());
            assertEquals(1, running.options.entries().size());
            assertThrows(SyncService.BadSync.class, () -> running.sync.sync(BODY));
        } finally {
            resume.countDown();
            worker.shutdownNow();
        }
    }

    @Test
    void unloadDoesNotBlockTheUiWhileAnImportNeedsTheUiThread() throws Exception {
        CountDownLatch importing = new CountDownLatch(1);
        CountDownLatch uiAvailable = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);
        ListenerManagerTest.FakeOptions options = new ListenerManagerTest.FakeOptions(export(USER_8080)) {
            @Override
            public void importListeners(String next) {
                if (first.getAndSet(false)) {
                    importing.countDown();
                    await(uiAvailable);
                }
                super.importListeners(next);
            }
        };
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try (Running running = new Running(options, new AddressAllocatorTest.FakeProbe())) {
            Future<?> request = workers.submit(() -> syncUntilStopped(running.sync));
            try {
                assertTrue(importing.await(3, TimeUnit.SECONDS));
                Future<?> uiUnload = workers.submit(running::unload);
                // The callback must return while the UI is still unavailable to the import.
                uiUnload.get(2, TimeUnit.SECONDS);
            } finally {
                uiAvailable.countDown();
            }
            request.get(3, TimeUnit.SECONDS);
            running.awaitCleanup();
            assertEquals(0, running.highlighter.registry().size());
            assertEquals(1, options.entries().size());
            assertTrue(options.has("127.0.0.1:8080"));
        } finally {
            uiAvailable.countDown();
            workers.shutdownNow();
        }
    }

    private static void syncUntilStopped(SyncService sync) {
        try {
            sync.sync(BODY);
        } catch (SyncService.BadSync expectedOnUnload) {
            // A request already admitted when unload starts must not publish a new assignment.
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError("test gate timed out");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    /** Real extension startup/shutdown and sync, faking only Burp persistence, sockets and UI. */
    private static final class Running implements AutoCloseable {
        final ListenerManagerTest.FakeOptions options;
        final ContainerHighlighter highlighter = new ContainerHighlighter();
        final SyncService sync;
        final ScheduledExecutorService timer;
        final MockedConstruction<ControlServer> servers;
        final MockedConstruction<AddressProbe.Sockets> probes;
        final MockedConstruction<HighlighterTab> panels;
        final AtomicReference<ExtensionUnloadingHandler> unloading = new AtomicReference<>();
        final AtomicBoolean unloaded = new AtomicBoolean();

        Running(ListenerManagerTest.FakeOptions options, AddressProbe probe) throws Exception {
            this.options = options;
            AtomicReference<ControlServer.Handler> handler = new AtomicReference<>();
            servers = mockConstruction(ControlServer.class, (server, construction) -> {
                handler.set((ControlServer.Handler) construction.arguments().get(0));
                when(server.start(anyString())).thenReturn(8079);
            });
            probes = mockConstruction(AddressProbe.Sockets.class, (sockets, construction) -> {
                when(sockets.probe(any())).thenAnswer(call -> probe.probe(call.getArgument(0)));
                when(sockets.answers(any())).thenAnswer(call -> probe.answers(call.getArgument(0)));
            });
            panels = mockConstruction(HighlighterTab.class);
            MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
            var preferenceStore = api.persistence().preferences();
            var projectStore = api.persistence().extensionData();
            var suite = api.burpSuite();
            var extension = api.extension();
            Map<String, String> preferences = new HashMap<>();
            Map<String, String> project = new HashMap<>();
            when(preferenceStore.getString(anyString())).thenAnswer(call -> preferences.get(call.getArgument(0)));
            doAnswer(call -> { preferences.put(call.getArgument(0), call.getArgument(1)); return null; })
                    .when(preferenceStore).setString(anyString(), anyString());
            when(projectStore.getString(anyString())).thenAnswer(call -> project.get(call.getArgument(0)));
            doAnswer(call -> { project.put(call.getArgument(0), call.getArgument(1)); return null; })
                    .when(projectStore).setString(anyString(), anyString());
            when(suite.exportProjectOptionsAsJson(ListenerConfig.PATH)).thenAnswer(call -> options.exportListeners());
            doAnswer(call -> { options.importListeners(call.getArgument(0)); return null; })
                    .when(suite).importProjectOptionsFromJson(anyString());
            doAnswer(call -> { unloading.set(call.getArgument(0)); return null; })
                    .when(extension).registerUnloadingHandler(any());
            highlighter.initialize(api);
            assertNotNull(handler.get(), "listener service initialized");
            sync = (SyncService) field(handler.get(), "sync");
            timer = (ScheduledExecutorService) field(highlighter, "leaseTimer");
        }

        void unload() {
            if (unloaded.compareAndSet(false, true)) unloading.get().extensionUnloaded();
        }

        void awaitCleanup() throws InterruptedException {
            assertTrue(timer.awaitTermination(3, TimeUnit.SECONDS), "listener cleanup finished");
        }

        public void close() throws Exception {
            try {
                unload();
                awaitCleanup();
            } finally {
                panels.close();
                probes.close();
                servers.close();
            }
        }

        private static Object field(Object owner, String name) throws Exception {
            Field field = owner.getClass().getDeclaredField(name);
            field.setAccessible(true);
            return field.get(owner);
        }
    }
}
