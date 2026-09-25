package burp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static burp.ListenerConfigTest.USER_8080;
import static burp.ListenerConfigTest.allInterfaces;
import static burp.ListenerConfigTest.at;
import static burp.ListenerConfigTest.export;
import static burp.ListenerConfigTest.specific;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AddressAllocatorTest {

    static final ListenerAddress PRESET = at("127.0.0.1:8080");
    static final ListenerAddress CONTROL = at("127.0.0.1:8079");

    /** A probe with a scripted view of which addresses other programs hold. */
    static final class FakeProbe implements AddressProbe {
        final Set<ListenerAddress> inUse = new HashSet<>();
        final Set<String> foreignHosts = new HashSet<>();
        final List<ListenerAddress> probed = new ArrayList<>();

        @Override
        public Result probe(ListenerAddress address) {
            probed.add(address);
            if (foreignHosts.contains(address.host())) {
                return Result.NOT_LOCAL;
            }
            return inUse.contains(address) ? Result.IN_USE : Result.FREE;
        }

        @Override
        public boolean answers(ListenerAddress address) {
            return true;
        }
    }

    private final FakeProbe probe = new FakeProbe();

    private AddressAllocator allocator(String burpExport, Set<ListenerAddress> owned) {
        return new AddressAllocator(PRESET, CONTROL, ListenerConfig.parse(burpExport), owned, probe);
    }

    private static AddressAllocator.Request container(String id) {
        return new AddressAllocator.Request(id, id, "red", null, null);
    }

    @Test
    void givesEachMarkedContainerTheNextAutomaticPortOnThePresetIp() {
        Map<String, AddressAllocator.Assignment> result = allocator(export(USER_8080), Set.of())
                .allocate(List.of(container("a"), container("b"), container("c")), Map.of());

        assertEquals(at("127.0.0.1:18080"), result.get("a").address());
        assertEquals(at("127.0.0.1:18081"), result.get("b").address());
        assertEquals(at("127.0.0.1:18082"), result.get("c").address());
    }

    @Test
    void skipsAPortADevServerAlreadyHolds() {
        probe.inUse.add(at("127.0.0.1:18080"));

        Map<String, AddressAllocator.Assignment> result = allocator(export(USER_8080), Set.of())
                .allocate(List.of(container("a")), Map.of());

        assertEquals(at("127.0.0.1:18081"), result.get("a").address());
    }

    @Test
    void skipsPortsAnyBurpListenerCoversIncludingAllInterfaces() {
        Map<String, AddressAllocator.Assignment> result = allocator(
                export(USER_8080, specific("127.0.0.1", 18080), allInterfaces(18081)), Set.of())
                .allocate(List.of(container("a")), Map.of());

        assertEquals(at("127.0.0.1:18082"), result.get("a").address());
    }

    @Test
    void usesARemotePresetsIp() {
        AddressAllocator remote = new AddressAllocator(at("192.168.10.2:8080"), at("192.168.10.2:8079"),
                ListenerConfig.parse(export(specific("192.168.10.2", 8080))), Set.of(), probe);

        assertEquals(at("192.168.10.2:18080"),
                remote.allocate(List.of(container("a")), Map.of()).get("a").address());
    }

    @Test
    void keepsCurrentHoldersFirstSoANewMarkCannotDisplaceThem() {
        Map<String, ListenerAddress> current = Map.of("z", at("127.0.0.1:18080"));

        Map<String, AddressAllocator.Assignment> result = allocator(export(USER_8080), Set.of(at("127.0.0.1:18080")))
                .allocate(List.of(container("a"), container("z")), current);

        assertEquals(at("127.0.0.1:18080"), result.get("z").address());
        assertEquals(at("127.0.0.1:18081"), result.get("a").address());
    }

    @Test
    void ownedAddressesSkipTheProbeWhichWouldFindOurOwnListener() {
        probe.inUse.add(at("127.0.0.1:18080")); // our own listener answers there

        Map<String, AddressAllocator.Assignment> result = allocator(export(USER_8080), Set.of(at("127.0.0.1:18080")))
                .allocate(List.of(container("a")), Map.of("a", at("127.0.0.1:18080")));

        assertEquals(at("127.0.0.1:18080"), result.get("a").address());
        assertFalse(probe.probed.contains(at("127.0.0.1:18080")));
    }

    @Test
    void honoursTheRememberedAddressWhenFree() {
        AddressAllocator.Request request =
                new AddressAllocator.Request("a", "A", "red", null, at("127.0.0.1:18085"));

        assertEquals(at("127.0.0.1:18085"),
                allocator(export(USER_8080), Set.of()).allocate(List.of(request), Map.of()).get("a").address());
    }

    @Test
    void fallsBackToAutomaticWhenTheRememberedAddressIsTaken() {
        probe.inUse.add(at("127.0.0.1:18085"));
        AddressAllocator.Request request =
                new AddressAllocator.Request("a", "A", "red", null, at("127.0.0.1:18085"));

        assertEquals(at("127.0.0.1:18080"),
                allocator(export(USER_8080), Set.of()).allocate(List.of(request), Map.of()).get("a").address());
    }

    @Test
    void neverAssignsThePresetOrControlAddress() {
        AddressAllocator.Request wantsPreset = new AddressAllocator.Request("a", "A", "red", null, PRESET);
        AddressAllocator.Request wantsControl = new AddressAllocator.Request("b", "B", "red", null, CONTROL);

        Map<String, AddressAllocator.Assignment> result = allocator(export(), Set.of())
                .allocate(List.of(wantsPreset, wantsControl), Map.of());

        assertEquals(at("127.0.0.1:18080"), result.get("a").address());
        assertEquals(at("127.0.0.1:18081"), result.get("b").address());
    }

    @Test
    void movesAContainerOffAnAddressThePresetNowUses() {
        // The user moved the preset onto 18080, which container "a" held.
        AddressAllocator moved = new AddressAllocator(at("127.0.0.1:18080"), CONTROL,
                ListenerConfig.parse(export(specific("127.0.0.1", 18080))), Set.of(), probe);

        Map<String, AddressAllocator.Assignment> result =
                moved.allocate(List.of(container("a")), Map.of("a", at("127.0.0.1:18080")));

        assertEquals(at("127.0.0.1:18081"), result.get("a").address());
    }

    @Test
    void usesAFreePinnedAddress() {
        AddressAllocator.Request pinned =
                new AddressAllocator.Request("a", "A", "red", at("127.0.0.1:9000"), null);

        AddressAllocator.Assignment assignment =
                allocator(export(USER_8080), Set.of()).allocate(List.of(pinned), Map.of()).get("a");

        assertEquals(at("127.0.0.1:9000"), assignment.address());
        assertFalse(assignment.adopted());
    }

    @Test
    void adoptsTheUsersOwnListenerAtAPinnedAddress() {
        AddressAllocator.Request pinned =
                new AddressAllocator.Request("a", "A", "red", at("192.168.10.5:8080"), null);

        AddressAllocator.Assignment assignment = allocator(export(USER_8080, specific("192.168.10.5", 8080)), Set.of())
                .allocate(List.of(pinned), Map.of()).get("a");

        assertEquals(at("192.168.10.5:8080"), assignment.address());
        assertTrue(assignment.adopted());
        assertFalse(assignment.allInterfaces());
    }

    @Test
    void adoptsAnAllInterfacesListenerAndSaysSo() {
        AddressAllocator.Request pinned =
                new AddressAllocator.Request("a", "A", "red", at("127.0.0.1:9090"), null);

        AddressAllocator.Assignment assignment = allocator(export(allInterfaces(9090)), Set.of())
                .allocate(List.of(pinned), Map.of()).get("a");

        assertTrue(assignment.adopted());
        assertTrue(assignment.allInterfaces());
    }

    @Test
    void reportsWhyAPinnedAddressCannotBeUsedAndNeverFallsBack() {
        probe.inUse.add(at("127.0.0.1:9000"));
        probe.foreignHosts.add("192.168.10.9");
        List<AddressAllocator.Request> requests = List.of(
                new AddressAllocator.Request("busy", "Busy", "red", at("127.0.0.1:9000"), null),
                new AddressAllocator.Request("foreign", "Foreign", "red", at("192.168.10.9:8080"), null),
                new AddressAllocator.Request("preset", "Preset", "red", PRESET, null),
                new AddressAllocator.Request("control", "Control", "red", CONTROL, null));

        Map<String, AddressAllocator.Assignment> result = allocator(export(), Set.of()).allocate(requests, Map.of());

        assertNull(result.get("busy").address());
        assertTrue(result.get("busy").error().contains("in use"), result.get("busy").error());
        assertTrue(result.get("foreign").error().contains("not an address"), result.get("foreign").error());
        assertTrue(result.get("preset").error().contains("preset"), result.get("preset").error());
        assertTrue(result.get("control").error().contains("control"), result.get("control").error());
    }

    @Test
    void refusesTheSamePinTwice() {
        List<AddressAllocator.Request> requests = List.of(
                new AddressAllocator.Request("a", "A", "red", at("127.0.0.1:9000"), null),
                new AddressAllocator.Request("b", "B", "red", at("127.0.0.1:9000"), null));

        Map<String, AddressAllocator.Assignment> result = allocator(export(), Set.of()).allocate(requests, new HashMap<>());

        assertEquals(at("127.0.0.1:9000"), result.get("a").address());
        assertTrue(result.get("b").error().contains("already pinned"), result.get("b").error());
    }

    @Test
    void anAutomaticContainerNeverTakesAnAddressAPinClaimedFirst() {
        // "a" sorts before "z", so only pins-first ordering keeps 18080 for the pin.
        List<AddressAllocator.Request> requests = List.of(
                container("a"),
                new AddressAllocator.Request("z", "Z", "red", at("127.0.0.1:18080"), null));

        Map<String, AddressAllocator.Assignment> result = allocator(export(), Set.of()).allocate(requests, Map.of());

        assertEquals(at("127.0.0.1:18080"), result.get("z").address());
        assertEquals(at("127.0.0.1:18081"), result.get("a").address());
    }
}
