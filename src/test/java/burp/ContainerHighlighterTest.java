package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.*;

class ContainerHighlighterTest {

    private static final String HEADER_NAME = "x-mac-container-color";

    @Test
    void highlightsInterceptedRequestWithoutStrippingHeaderAtReceiveStage() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpHeader colorHeader = mock(HttpHeader.class);
        when(colorHeader.name()).thenReturn("X-Mac-Container-Color");
        when(colorHeader.value()).thenReturn(" Blue ");

        Annotations annotations = mock(Annotations.class);
        Annotations blueAnnotations = mock(Annotations.class);
        when(annotations.withHighlightColor(HighlightColor.BLUE)).thenReturn(blueAnnotations);

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        when(interceptedRequest.headers()).thenReturn(List.of(colorHeader));
        when(interceptedRequest.annotations()).thenReturn(annotations);

        ProxyRequestReceivedAction expectedAction = mock(ProxyRequestReceivedAction.class);
        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(interceptedRequest, blueAnnotations))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleRequestReceived(interceptedRequest));
        }

        verify(interceptedRequest, never()).withRemovedHeader(HEADER_NAME);
    }

    @Test
    void stripsResponseHeaderOnlyForRequestsThatContainedMarkerHeader() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpHeader colorHeader = mock(HttpHeader.class);
        when(colorHeader.name()).thenReturn("X-Mac-Container-Color");
        when(colorHeader.value()).thenReturn(" Blue ");

        Annotations annotations = mock(Annotations.class);
        Annotations blueAnnotations = mock(Annotations.class);
        when(annotations.withHighlightColor(HighlightColor.BLUE)).thenReturn(blueAnnotations);

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        when(interceptedRequest.headers()).thenReturn(List.of(colorHeader));
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(HEADER_NAME)).thenReturn(cleanRequest);
        when(interceptedRequest.messageId()).thenReturn(7);

        ProxyRequestToBeSentAction expectedRequestAction = mock(ProxyRequestToBeSentAction.class);
        try (MockedStatic<ProxyRequestToBeSentAction> requestActionStatic = mockStatic(ProxyRequestToBeSentAction.class)) {
            requestActionStatic.when(() -> ProxyRequestToBeSentAction.continueWith(cleanRequest, blueAnnotations))
                               .thenReturn(expectedRequestAction);

            assertSame(expectedRequestAction, highlighter.handleRequestToBeSent(interceptedRequest));
        }

        InterceptedResponse interceptedResponse = mock(InterceptedResponse.class);
        HttpResponse cleanResponse = mock(HttpResponse.class);
        when(interceptedResponse.messageId()).thenReturn(7);
        when(interceptedResponse.hasHeader(HEADER_NAME)).thenReturn(true);
        when(interceptedResponse.withRemovedHeader(HEADER_NAME)).thenReturn(cleanResponse);

        ProxyResponseToBeSentAction expectedResponseAction = mock(ProxyResponseToBeSentAction.class);
        try (MockedStatic<ProxyResponseToBeSentAction> responseActionStatic = mockStatic(ProxyResponseToBeSentAction.class)) {
            responseActionStatic.when(() -> ProxyResponseToBeSentAction.continueWith(cleanResponse))
                                .thenReturn(expectedResponseAction);

            assertSame(expectedResponseAction, highlighter.handleResponseToBeSent(interceptedResponse));
        }
    }

    @Test
    void leavesLegitimateResponseHeaderAloneWhenRequestWasNotTagged() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        InterceptedResponse interceptedResponse = mock(InterceptedResponse.class);
        when(interceptedResponse.messageId()).thenReturn(99);
        when(interceptedResponse.hasHeader(HEADER_NAME)).thenReturn(true);

        try (MockedStatic<ProxyResponseToBeSentAction> responseActionStatic = mockStatic(ProxyResponseToBeSentAction.class)) {
            ProxyResponseToBeSentAction expectedAction = mock(ProxyResponseToBeSentAction.class);
            responseActionStatic.when(() -> ProxyResponseToBeSentAction.continueWith(interceptedResponse))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleResponseToBeSent(interceptedResponse));
            verify(interceptedResponse, never()).withRemovedHeader(HEADER_NAME);
        }
    }
}
