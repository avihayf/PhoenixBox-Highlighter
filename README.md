# PhoenixBox Highlighter

A Burp Suite extension that colours proxy history by [PhoenixBox](https://github.com/avihayf/PhoenixBox) container, and notes which container each request came from. It works in two modes:

- **Paired with PhoenixBox (automatic, one click in Burp):** each container with an open tab in PhoenixBox (while its Highlighter switch is on) gets its own Burp proxy listener, opened by this extension. The extension recognises the container by the listener a request arrives on (`listenerInterface()`). Requests carry no extra header, and are forwarded exactly as the browser sent them.
- **Not paired:** PhoenixBox marks a container's requests with an `x-mac-container-color` header, as it does for the old v1.x Highlighter. The extension colours the request from it and strips the header before it goes anywhere.

## How It Works

```
   Firefox + PhoenixBox
        │  1. open containers ────────────────▶  control server (127.0.0.1:8079, token)
        │                                         opens a listener per container,
        │  ◀── Work → 127.0.0.1:18081 ────────── e.g. Work → 127.0.0.1:18081
        │
        │  2. Work's traffic → 127.0.0.1:18081
        ▼
   Burp Proxy ─ arrived on Work's listener:
        │         highlight red, note "Work"
        ▼
   Target Server   (receives the request unchanged)
```

- PhoenixBox sends the **full list** of open containers whenever it changes and every 10 seconds.
  A container's listener opens with its first tab and closes 30 seconds after its last one.
  The extension reconciles its listeners to that list, so nothing drifts after a missed message or
  a restart on either side.
- Closing Firefox's last window closes the container listeners 30 seconds later, leaving only your own. If
  Firefox quits or crashes without saying so, they close after **30 seconds** without an update. They
  come back when Firefox does.
- Listeners are Burp **project** settings. The extension only adds and removes listeners it created,
  remembers them with the project, removes leftovers after a crash, and removes all of them when it
  is unloaded. Changing listeners makes Burp restart all of them, yours included, so it only does
  so when the set actually changes.

## Pairing

Pairing is automatic, with one click in Burp:
1. PhoenixBox looks for this extension on its Burp proxy's host (`POST /v1/hello`) and asks to pair (`POST /v1/pair`).
2. The request appears at the top of Burp's **PhoenixBox** tab, with **Allow / Deny**, the requesting extension's `moz-extension://` origin and its client ID.
3. Allowing gives that PhoenixBox its own token.

One PhoenixBox is paired at a time. Each sends its full list of open containers, so two would overwrite each other's listeners. Allowing a new one, such as a new Firefox profile, replaces the old pairing, and its token stops working. The tab shows who is paired, with **Unpair**, which also replaces the manual pairing string, `phx1:<host>:<port>:<token>`. That string is the fallback when PhoenixBox can't find Burp.

The Allow click is the security gate. Without it, another Firefox extension or a local program could make Burp open listeners. The control server listens where Burp's first proxy listener does (loopback, a specific IP, or all interfaces), on port 8079, or the next port up to 8099 if 8079 is taken.
- Discovery and pairing need a Firefox extension's `Origin` (`moz-extension://…`), which web pages can't send.
- Everything else needs a token.
- CORS preflights are always refused.

A website therefore can't reach it.

## Listener Addresses

Automatic listeners use the IP of PhoenixBox's **Burp Suite** preset and the first usable port from
**18080** upward (clear of ports that dev servers commonly use, such as 8081–8090). An address is never used if it:

- is the preset's own address,
- overlaps one of your listeners (an *all interfaces* listener covers its port on every IP),
- is the control server's address,
- is already in use by another program. A connect test catches anything listening, including a dev
  server on `0.0.0.0`, so its port is never quietly taken over; a bind test then confirms the IP
  belongs to this machine. A port whose listener has only just closed counts as free.

A container keeps its address, and gets it back the next time it opens. In PhoenixBox a container
can be **pinned** to an exact `ip:port`. If you already built a listener there (say, with invisible
proxying), the extension uses it as-is and never modifies or removes it.

## Supported Colors

| PhoenixBox container colour | Burp Highlight |
|-----------------------------|----------------|
| blue                        | Blue           |
| turquoise                   | Cyan           |
| green                       | Green          |
| yellow                      | Yellow         |
| orange                      | Orange         |
| red                         | Red            |
| pink                        | Pink           |
| purple                      | Magenta        |

Firefox's *toolbar* colour has no Burp equivalent: those containers are named but not highlighted.

## Notes Column

Traffic from a highlighted container gets the **container name** as its note, e.g. `Work`; the highlight
carries the colour. A note you already wrote is never overwritten.

## Not Paired: the Colour Header

While no PhoenixBox is paired, PhoenixBox marks containers with an `x-mac-container-color` header, as it does for the old v1.x Highlighter. It never sends the container name.
- The request is coloured, with no note.
- `x-mac-container-*` headers are stripped at the Proxy receive stage, and again for every tool before a request is sent, so they don't reach a target.

**While paired**, PhoenixBox sends no header, so this extension neither reads nor strips them. It is in paired mode while a paired PhoenixBox has synced within the last 30 seconds and hasn't unpaired. Unpairing, revoking the pairing, closing Firefox's last window, or 30 seconds of silence switch it back.

## Sending to Repeater

Right-click a request and choose **Extensions > PhoenixBox Highlighter > Send to Repeater
(PhoenixBox)**. It names the new tab `<number> <container>` — `1 Attacker`, `2 Admin` — so container
attribution survives into Repeater, where tabs cannot otherwise be colored.

> [!NOTE]
> Burp files every extension's items under that extension's own name, so the route is three levels
> deep. Nothing in the API controls this — `provideMenuItems` returns components and Burp decides
> where they go.

The label is read from the note recorded at the receive stage (the container's name), so the entry
works from **HTTP history** as well as **Proxy > Intercept**. For requests labelled by an older,
header-based PhoenixBox it falls back to the colour (`1 red`) when no name was sent.

> [!NOTE]
> Burp's Repeater API exposes a tab *name* and nothing else — tabs cannot be tinted by an extension,
> and the tab number cannot be read back, so the extension keeps its own counter. If you mix this
> entry with Burp's built-in **Send to Repeater**, the two sequences drift apart.

Container names are capped at 64 characters and stripped of control characters before they become a
note or a tab label.

## Requirements

- **PhoenixBox** Firefox extension **3.1.0 or later** — [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/phoenixbox/) · [GitHub](https://github.com/avihayf/PhoenixBox)
- Burp Suite (Community or Pro)
- Java 17+ (for building from source)

## Installation

1. Install the **PhoenixBox** Firefox extension:
   - From the Firefox Add-ons store: [addons.mozilla.org/en-US/firefox/addon/phoenixbox](https://addons.mozilla.org/en-US/firefox/addon/phoenixbox/)
   - Or directly from GitHub: [github.com/avihayf/PhoenixBox](https://github.com/avihayf/PhoenixBox)
2. Download the latest `PhoenixBoxHighlighter-<version>.jar` from the [Releases](https://github.com/avihayf/PhoenixBox-Highlighter/releases) page,  
   or [build from source](#building--testing).
3. In Burp Suite, go to **Extensions > Installed > Add**.
4. Set **Extension type** to **Java** and select the JAR.
5. Check the version: the Extensions list shows **PhoenixBox Highlighter v2.0.0**, and Burp has a
   new **PhoenixBox** tab.
6. In PhoenixBox, select the **Burp Suite** proxy preset and turn on the **Highlighter** tile.
   When Burp asks whether to pair PhoenixBox, click **Allow**.

## Building & Testing

```bash
# Run tests
./gradlew test

# Build JAR (build/libs/PhoenixBoxHighlighter-<version>.jar)
./gradlew clean jar
```

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).

## Credits

Inspired by [PwnFox](https://github.com/yeswehack/PwnFox).

## Author

0xR3DB0MB
