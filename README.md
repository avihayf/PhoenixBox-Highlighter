# PhoenixBox Highlighter

A Burp Suite extension that colours proxy history by [PhoenixBox](https://github.com/avihayf/PhoenixBox) container, and notes which container each request came from, **without anything being added to the request**.

Each container you mark in PhoenixBox gets its own Burp proxy listener, opened by this extension. PhoenixBox sends that container's traffic to its listener, and the extension recognises the container by the listener a request arrives on (`listenerInterface()`), so the request is forwarded exactly as the browser sent it.

## How It Works

```
   Firefox + PhoenixBox
        │  1. marked containers ──────────────▶  control server (127.0.0.1:8079, token)
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

- PhoenixBox sends the **full list** of marked containers whenever it changes and every 30 seconds.
  The extension reconciles its listeners to that list, so nothing drifts after a missed message or
  a restart on either side.
- With no update for **120 seconds** (Firefox closed), the extension closes its listeners. They come
  back on the next update.
- Listeners are Burp **project** settings. The extension only adds and removes listeners it created,
  remembers them with the project, removes leftovers after a crash, and removes all of them when it
  is unloaded. Changing listeners makes Burp restart all of them, yours included, so it only does
  so when the set actually changes.

## Pairing

The **PhoenixBox** tab shows a pairing string, `phx1:<host>:<port>:<token>`. Paste it into PhoenixBox
once. **New token** revokes it.

The control server listens where Burp's first proxy listener does (loopback, a specific IP, or all
interfaces), on port 8079 or the next free port up to 8099. Every request needs the token; requests
carrying a web page `Origin`, and all CORS preflights, are refused, so a website cannot reach it.

## Listener Addresses

Automatic listeners use the IP of PhoenixBox's **Burp Suite** preset and the first usable port from
**18080** upward (clear of ports that dev servers commonly use, such as 8081–8090). An address is never used if it:

- is the preset's own address,
- overlaps one of your listeners (an *all interfaces* listener covers its port on every IP),
- is the control server's address,
- is already in use by another program. A connect test catches anything listening, including a dev
  server on `0.0.0.0`, so its port is never quietly taken over; a bind test then confirms the IP
  belongs to this machine. A port whose listener has only just closed counts as free.

A container keeps its address, and gets it back the next time it is marked. In PhoenixBox a container
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

Traffic from a marked container gets the **container name** as its note, e.g. `Work`; the highlight
carries the colour. A note you already wrote is never overwritten.

## Older PhoenixBox Versions

PhoenixBox before 3.1.0 added `x-mac-container-color` (and briefly `x-mac-container-name`) headers
instead. This extension still honours them and **always strips both**, at the Proxy receive stage and
again for every tool before a request is sent, so they never reach a target.

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
6. Pair: copy the pairing string from the **PhoenixBox** tab into PhoenixBox's **Highlighter** tile,
   then mark containers with the highlighter button in PhoenixBox's container list.

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
