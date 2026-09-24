# PhoenixBox Highlighter

A Burp Suite extension that automatically color-highlights proxy history entries based on the `x-mac-container-color` HTTP header injected by the [PhoenixBox](https://github.com/avihayf/PhoenixBox) Firefox extension, and labels Repeater tabs using the companion `x-mac-container-name` header.

When a request arrives with these headers, the matching highlight color is applied, the container is recorded as a note, and both headers are stripped — all at the moment the Proxy receives the request, so the headers never appear in HTTP history, in the Intercept editor, or on the wire to the target.

## How It Works

[PhoenixBox](https://github.com/avihayf/PhoenixBox) is a Firefox extension for multi-container colored browsing. One of its features, **Paint the Burp**, adds an `x-mac-container-color` header to proxied requests so Burp can visually associate each request with its source container.

PhoenixBox Highlighter reads that header and maps it to a highlight color in the proxy history — letting you instantly tell which container each request came from.

```
Firefox Container (PhoenixBox)
        │
        │  x-mac-container-color: red
        │  x-mac-container-name:  Attacker
        ▼
   Burp Suite Proxy  (request received)
        │
        ├─ highlight the entry red
        ├─ record "🔴 Attacker" as a note (shows in the Notes column)
        ├─ strip both headers
        ▼
   Target Server   (never sees either header)
```

## Supported Colors

| Header Value | Burp Highlight |
|--------------|----------------|
| `blue`       | Blue           |
| `cyan`       | Cyan           |
| `green`      | Green          |
| `yellow`     | Yellow         |
| `orange`     | Orange         |
| `red`        | Red            |
| `pink`       | Pink           |
| `magenta`    | Magenta        |

Header values are case-insensitive and leading/trailing whitespace is ignored. A value outside this
list is logged to **Extensions > Output** and leaves the entry unhighlighted — the header is still
stripped.

## Notes Column

Because Burp's HTTP history renders the request **as the browser sent it**, the headers stay visible
in that default view even though they are stripped — switch the request pane to **Edited request** to
see what Burp actually forwarded. So the container is also recorded as a note, which travels with the
entry and needs no header at all:

| Container color | Note |
|---|---|
| `red` | 🔴 Attacker |
| `orange` | 🟠 Attacker |
| `yellow` | 🟡 Attacker |
| `green` | 🟢 Attacker |
| `blue` | 🔵 Attacker |
| `cyan` | 💠 Attacker |
| `pink` | 💗 Attacker |
| `magenta` | 🟣 Attacker |

An unrecognized color uses ⚪. Emoji has no cyan or pink *circle* — the round set covers only
red/orange/yellow/green/blue/purple/brown/black/white — so those two use the closest correctly-hued
glyph rather than collapsing into 🔵 and 🟣, which would erase the distinction PhoenixBox draws
between blue/turquoise and pink/purple containers.

The marker is also how the extension recognizes its own notes, so a note you write by hand is never
overwritten and never mistaken for container attribution.

## Header Stripping

PhoenixBox sends two headers, and both are only ever meant to travel from Firefox to Burp:

| Header | Value | Purpose |
|---|---|---|
| `x-mac-container-color` | bare color name | picks the highlight color |
| `x-mac-container-name`  | percent-encoded UTF-8 | labels the Repeater tab |

Both are removed at two independent points:

1. The Proxy handler strips them **when the request is received** — before it is written to HTTP
   history, shown in the Intercept editor, or sent. The container is preserved as a note instead, so
   nothing is lost.
2. An HTTP handler strips them from **every** Burp tool, so requests captured into Repeater or
   Intruder before this extension was loaded cannot leak them when you resend them.

Stripping happens even when the color is not one we recognize, and even when the name header
arrives without a color header alongside it.

> [!NOTE]
> If Burp is configured to pass a host through without interception (e.g. a TLS pass-through rule),
> the extension never sees the request and cannot strip the headers. Enable the PhoenixBox header
> option only for hosts that are actually proxied.

## Sending to Repeater

Right-click a request and choose **Extensions > PhoenixBox Highlighter > Send to Repeater
(PhoenixBox)**. It names the new tab `<number> <container>` — `1 Attacker`, `2 Admin` — so container
attribution survives into Repeater, where tabs cannot otherwise be colored.

> [!NOTE]
> Burp files every extension's items under that extension's own name, so the route is three levels
> deep. Nothing in the API controls this — `provideMenuItems` returns components and Burp decides
> where they go.

The label is read from the note recorded at the receive stage, so the entry works from **HTTP
history** as well as **Proxy > Intercept** — even though the headers themselves are long gone by the
time the request reaches history. The label prefers the container's name and falls back to its color
(`1 red`) when no name was sent (an older PhoenixBox).

> [!NOTE]
> Burp's Repeater API exposes a tab *name* and nothing else — tabs cannot be tinted by an extension,
> and the tab number cannot be read back, so the extension keeps its own counter. If you mix this
> entry with Burp's built-in **Send to Repeater**, the two sequences drift apart.

Container names are percent-encoded on the wire, decoded here, and stripped of control characters
before they become a tab label.

## Requirements

- **PhoenixBox** Firefox extension — [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/phoenixbox/) · [GitHub](https://github.com/avihayf/PhoenixBox)
- Burp Suite (Community or Pro)
- Java 17+ (for building from source)

## Installation

1. Install the **PhoenixBox** Firefox extension:
   - From the Firefox Add-ons store: [addons.mozilla.org/en-US/firefox/addon/phoenixbox](https://addons.mozilla.org/en-US/firefox/addon/phoenixbox/)
   - Or directly from GitHub: [github.com/avihayf/PhoenixBox](https://github.com/avihayf/PhoenixBox)
2. Download the latest `PhoenixBoxHighlighter.jar` from the [Releases](https://github.com/avihayf/PhoenixBox-Highlighter/releases) page,  
   or [build from source](#building--testing).
3. In Burp Suite, go to **Extensions > Installed > Add**.
4. Set **Extension type** to **Java** and select the JAR.

## Building & Testing

```bash
# Run tests
./gradlew test

# Build JAR
./gradlew clean jar
```

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).

## Credits

Inspired by [PwnFox](https://github.com/yeswehack/PwnFox).

## Author

0xR3DB0MB
