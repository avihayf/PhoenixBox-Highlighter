/**
 * @author 0xR3DB0MB
 */
package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ContainerHighlighter implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler {

    private static final String HEADER_NAME = "x-mac-container-color";

    private static final Map<String, HighlightColor> COLOR_MAP = Map.of(
            "blue", HighlightColor.BLUE,
            "cyan", HighlightColor.CYAN,
            "green", HighlightColor.GREEN,
            "yellow", HighlightColor.YELLOW,
            "orange", HighlightColor.ORANGE,
            "red", HighlightColor.RED,
            "pink", HighlightColor.PINK,
            "magenta", HighlightColor.MAGENTA
    );

    private final Set<Integer> responseCleanupMessageIds = ConcurrentHashMap.newKeySet();

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("PhoenixBox Highlighter");
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.logging().logToOutput("PhoenixBox Highlighter loaded");
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        String colorValue = null;

        for (HttpHeader header : interceptedRequest.headers()) {
            if (header.name().equalsIgnoreCase(HEADER_NAME)) {
                colorValue = header.value().trim().toLowerCase(Locale.ROOT);
                break;
            }
        }

        if (colorValue == null) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }

        HighlightColor highlight = COLOR_MAP.get(colorValue);
        Annotations annotations = interceptedRequest.annotations();

        if (highlight != null) {
            annotations = annotations.withHighlightColor(highlight);
        }

        responseCleanupMessageIds.add(interceptedRequest.messageId());
        HttpRequest cleanRequest = interceptedRequest.withRemovedHeader(HEADER_NAME);

        return ProxyRequestToBeSentAction.continueWith(cleanRequest, annotations);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        boolean shouldStripHeader = responseCleanupMessageIds.remove(interceptedResponse.messageId());

        if (shouldStripHeader && interceptedResponse.hasHeader(HEADER_NAME)) {
            HttpResponse cleanResponse = interceptedResponse.withRemovedHeader(HEADER_NAME);
            return ProxyResponseToBeSentAction.continueWith(cleanResponse);
        }

        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
