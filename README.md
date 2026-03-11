# PhoenixBox Highlighter

A Burp Suite extension that automatically color-highlights proxy history entries based on the `x-mac-container-color` HTTP header. Requests arriving with this header get highlighted in Burp's UI, and the header is stripped before forwarding to the target server.

This is useful when working with Firefox Multi-Account Containers and `PhoenixBox` — each container can inject a color header through a companion browser extension, and PhoenixBox Highlighter maps that to Burp's highlight colors so you can visually distinguish traffic from different contexts at a glance.

## Prerequisites

- Install the companion Firefox extension that injects `x-mac-container-color`.
- Use Burp Suite with Java 17+ available for builds.

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

## Building

Requires Java 17+.

```bash
./gradlew clean shadowJar
```

The output JAR is at `build/libs/PhoenixBoxHighlighter.jar`.

## Installation

1. Install and configure the companion Firefox extension first.
2. Build the JAR from source using the Gradle wrapper (see above).
3. In Burp Suite, go to **Extensions > Installed > Add**.
4. Set **Extension type** to **Java** and select the JAR file.

## How It Works

PhoenixBox Highlighter registers as both a proxy request handler and a proxy response handler:

- **Requests**: Reads the `x-mac-container-color` header, applies the matching highlight color to the proxy history entry, and removes the header before the request is sent to the target.
- **Responses**: Strips the `x-mac-container-color` header only for responses tied to requests that originally carried the marker header.

## License

Mozilla Public License 2.0. See `LICENSE`.

## Credits

Inspired by [PwnFox](https://github.com/yeswehack/PwnFox).

## Author

0xR3DB0MB