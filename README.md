# PhoenixBox Highlighter

A Burp Suite extension that automatically color-highlights proxy history entries based on the `x-mac-container-color` HTTP header injected by the [PhoenixBox](https://github.com/avihayf/PhoenixBox) Firefox extension.

When a request arrives with this header, the matching highlight color is applied in Burp's proxy history and the header is stripped before the request is forwarded to the target server.

## How It Works

[PhoenixBox](https://github.com/avihayf/PhoenixBox) is a Firefox extension that leverages [Firefox Multi-Account Containers](https://support.mozilla.org/en-US/kb/containers) to isolate browsing sessions. It injects an `x-mac-container-color` header into every proxied request, carrying the color of the active container.

PhoenixBox Highlighter picks up that header in Burp and maps it to a highlight color in the proxy history — letting you instantly see which container each request came from.

```
Firefox Container (PhoenixBox)
        │
        │  x-mac-container-color: red
        ▼
   Burp Suite Proxy
        │
        ├─ highlight entry red in proxy history
        ├─ strip x-mac-container-color from request
        ▼
   Target Server
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

Header values are case-insensitive and leading/trailing whitespace is ignored.

## Requirements

- [PhoenixBox](https://github.com/avihayf/PhoenixBox) Firefox extension
- Burp Suite (Community or Pro)
- Java 17+ (for building from source)

## Installation

1. Install the **PhoenixBox** Firefox extension and configure your containers.
2. Build the JAR:

   ```bash
   ./gradlew clean shadowJar
   ```

   Output: `build/libs/PhoenixBoxHighlighter.jar`

3. In Burp Suite, go to **Extensions > Installed > Add**.
4. Set **Extension type** to **Java** and select the JAR.

## Building & Testing

```bash
# Run tests
./gradlew test

# Build JAR
./gradlew clean shadowJar
```

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).

## Credits

Inspired by [PwnFox](https://github.com/yeswehack/PwnFox).

## Author

0xR3DB0MB
