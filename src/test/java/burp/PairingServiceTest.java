package burp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PairingServiceTest {

    private static final String ORIGIN = "moz-extension://1b2c3d4e-0000-4000-8000-000000000001";
    private static final String CLIENT = "client-abcdefghijklmnop";

    private final AtomicLong now = new AtomicLong(1_000);

    /** Keeps the stored JSON, like Burp's preferences would. */
    private static final class MemoryStore implements PairingService.Store {
        String json;

        @Override
        public String get() {
            return json;
        }

        @Override
        public void set(String value) {
            json = value;
        }
    }

    @Test
    void anUnansweredRequestExpiresSoAnotherCanAsk() {
        PairingService pairing = new PairingService(null, "manual", now::get);
        List<PairingService.Pending> prompts = new ArrayList<>();
        pairing.setPrompt(prompts::add);

        pairing.request(CLIENT, "A", ORIGIN);
        assertEquals(PairingService.Status.BUSY, pairing.request("other-client-abcdefghij", "B", ORIGIN).status());

        now.addAndGet(PairingService.PENDING_TIMEOUT_MS + 1);
        assertNull(pairing.pending());
        assertEquals(PairingService.Status.PENDING, pairing.request("other-client-abcdefghij", "B", ORIGIN).status());
        assertEquals(2, prompts.size());
    }

    @Test
    void forgetsADenialAfterAWhileSoConnectCanAskAgain() {
        PairingService pairing = new PairingService(null, "manual", now::get);
        pairing.request(CLIENT, "A", ORIGIN);
        pairing.decide(CLIENT, false);
        assertEquals(PairingService.Status.DENIED, pairing.request(CLIENT, "A", ORIGIN).status());

        now.addAndGet(PairingService.DENIAL_MS + 1);
        assertEquals(PairingService.Status.PENDING, pairing.request(CLIENT, "A", ORIGIN).status());
    }

    @Test
    void approvedClientsSurviveARestart() {
        MemoryStore store = new MemoryStore();
        PairingService pairing = new PairingService(store, "manual", now::get);
        pairing.request(CLIENT, "Firefox", ORIGIN);
        pairing.decide(CLIENT, true);
        String token = pairing.request(CLIENT, "Firefox", ORIGIN).token();

        PairingService restarted = new PairingService(store, "manual", now::get);

        assertEquals(PairingService.Status.APPROVED, restarted.request(CLIENT, "Firefox", ORIGIN).status());
        assertTrue(restarted.isAuthorized("Bearer " + token));
        assertFalse(restarted.isAuthorized("Bearer wrong"));
        assertFalse(restarted.isAuthorized(token));
    }

    @Test
    void ignoresAnAnswerAboutARequestThatIsNoLongerWaiting() {
        PairingService pairing = new PairingService(null, "manual", now::get);
        pairing.decide(CLIENT, true);

        assertTrue(pairing.clients().isEmpty());
    }

    @Test
    void cleansTheLabelShownInBurp() {
        assertEquals("PhoenixBox", PairingService.cleanLabel("  \u0000 "));
        assertEquals("FirefoxEvil", PairingService.cleanLabel("Firefox\r\nEvil"));
        assertEquals(64, PairingService.cleanLabel("x".repeat(200)).length());
    }
}
