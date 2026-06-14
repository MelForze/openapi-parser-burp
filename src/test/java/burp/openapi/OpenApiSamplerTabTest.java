package burp.openapi;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.repeater.Repeater;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

final class OpenApiSamplerTabTest
{
    @BeforeAll
    static void setupMontoyaFactory()
    {
        MontoyaFactoryBootstrap.install();
    }

    @Test
    void basicTabMetadataAndComponentExist()
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        assertEquals("OpenAPI Sampler", tab.tabTitle());
        assertNotNull(tab.uiComponent());
    }

    @Test
    void provideMenuItemsReturnsEmptyForIrrelevantEvents()
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        assertTrue(tab.provideMenuItems((ContextMenuEvent) null).isEmpty());

        ContextMenuEvent event = mock(ContextMenuEvent.class);
        when(event.isFromTool(ToolType.TARGET)).thenReturn(false);
        assertTrue(tab.provideMenuItems(event).isEmpty());
    }

    @Test
    void provideMenuItemsDetectsOpenApiUrlAndBody()
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        HttpRequestResponse urlResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://api.example/openapi.json");
        when(urlResponse.request()).thenReturn(request);
        when(urlResponse.response()).thenReturn(null);

        ContextMenuEvent urlEvent = mock(ContextMenuEvent.class);
        when(urlEvent.isFromTool(ToolType.TARGET)).thenReturn(true);
        when(urlEvent.selectedRequestResponses()).thenReturn(List.of(urlResponse));
        assertEquals(1, tab.provideMenuItems(urlEvent).size());

        HttpRequestResponse bodyResponse = mock(HttpRequestResponse.class);
        HttpRequest noSpecRequest = mock(HttpRequest.class);
        when(noSpecRequest.url()).thenReturn("https://api.example/index.html");
        HttpResponse response = mock(HttpResponse.class);
        when(response.bodyToString()).thenReturn("""
                openapi: 3.0.1
                paths:
                  /users:
                    get:
                      summary: list
                """);
        when(bodyResponse.request()).thenReturn(noSpecRequest);
        when(bodyResponse.response()).thenReturn(response);

        ContextMenuEvent bodyEvent = mock(ContextMenuEvent.class);
        when(bodyEvent.isFromTool(ToolType.TARGET)).thenReturn(true);
        when(bodyEvent.selectedRequestResponses()).thenReturn(List.of(bodyResponse));
        assertEquals(1, tab.provideMenuItems(bodyEvent).size());
    }

    @Test
    void parseSpecAcceptsValidInputAndRejectsInvalidInput() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        String valid = """
                openapi: 3.0.3
                info:
                  title: Sample
                  version: 1.0.0
                paths:
                  /users:
                    get:
                      operationId: listUsers
                      responses:
                        '200':
                          description: ok
                """;

        Object parseOutcome = invoke(tab, "parseSpec",
                new Class<?>[]{String.class, String.class, String.class, boolean.class},
                valid, "inline", "inline", false);
        assertNotNull(parseOutcome);

        Exception thrown = null;
        try
        {
            invoke(tab, "parseSpec",
                    new Class<?>[]{String.class, String.class, String.class, boolean.class},
                    "not-openapi", "inline", "inline", false);
        }
        catch (Exception ex)
        {
            thrown = ex;
        }
        assertNotNull(thrown);
        assertTrue(Utils.nonBlank(thrown.getMessage()));
    }

    @Test
    void parseSpecBlocksRemoteExternalRefsOwnedBySwaggerParser() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        String spec = """
                openapi: 3.0.3
                info:
                  title: Remote ref test
                  version: 1.0.0
                paths:
                  /users:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              $ref: 'http://127.0.0.1:9/evil.yaml#/components/schemas/User'
                      responses:
                        '200':
                          description: ok
                """;

        Object parseOutcome = invoke(tab, "parseSpec",
                new Class<?>[]{String.class, String.class, String.class, boolean.class},
                spec, "inline", "inline", false);
        SwaggerParseResult parseResult = (SwaggerParseResult) recordValue(parseOutcome, "parseResult");

        assertNotNull(parseResult);
        assertTrue(
                parseResult.getMessages().stream().anyMatch(message ->
                        message.contains("denylist")
                                || message.contains("restricted")
                                || message.contains("Unable to load URL ref")),
                "remote external refs should be blocked before Swagger parser can fetch them directly"
        );
    }

    @Test
    void urlListParsingHelpersWork() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        String normalizedQuoted = (String) invoke(tab, "normalizeToken", new Class<?>[]{String.class}, "\"api.example/openapi.json\"");
        assertEquals("api.example/openapi.json", normalizedQuoted);

        String normalizedComment = (String) invoke(tab, "normalizeToken", new Class<?>[]{String.class}, "api.example/openapi.json # note");
        assertEquals("api.example/openapi.json", normalizedComment);

        @SuppressWarnings("unchecked")
        List<String> tokens = (List<String>) invoke(tab, "csvTokens", new Class<?>[]{String.class}, "svc;https://api.example/openapi.json;note");
        assertEquals(List.of("svc", "https://api.example/openapi.json", "note"), tokens);

        boolean bareHost = (boolean) invoke(tab, "looksLikeBareUrlCandidate", new Class<?>[]{String.class}, "api.example/openapi.json");
        assertTrue(bareHost);

        boolean relative = (boolean) invoke(tab, "looksLikeBareUrlCandidate", new Class<?>[]{String.class}, "/openapi.json");
        assertFalse(relative);
    }

    @Test
    void formatParseErrorsProvidesFallbackText() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        String fromNull = (String) invoke(tab, "formatParseErrors", new Class<?>[]{SwaggerParseResult.class}, (Object) null);
        assertTrue(fromNull.contains("no model"));

        SwaggerParseResult parseResult = new SwaggerParseResult();
        parseResult.setMessages(List.of("line1", "line2"));
        String fromMessages = (String) invoke(tab, "formatParseErrors", new Class<?>[]{SwaggerParseResult.class}, parseResult);
        assertEquals("line1\nline2", fromMessages);
    }

    @Test
    void selectedServerFiltersVisibleRows() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        OpenApiSamplerTable table = (OpenApiSamplerTable) field(tab, "table");
        @SuppressWarnings("unchecked")
        JComboBox<?> sourceSelector = (JComboBox<?>) field(tab, "sourceSelector");
        @SuppressWarnings("unchecked")
        JComboBox<String> selector = (JComboBox<String>) field(tab, "serverSelector");

        model.load(spec("https://one.example", "/users"), "https://one.example/openapi.json", "one");
        model.load(spec("https://two.example", "/orders"), "https://two.example/openapi.json", "two");

        invoke(tab, "refreshSourceSelector", new Class<?>[]{});
        invoke(tab, "refreshServerSelector", new Class<?>[]{});
        invoke(tab, "applyFilter", new Class<?>[]{});
        assertEquals(2, table.visibleOperations().size());

        selector.setSelectedItem("https://one.example");
        invoke(tab, "applyFilter", new Class<?>[]{});
        assertEquals(1, table.visibleOperations().size());
        assertEquals("/users", table.visibleOperations().get(0).path());

        sourceSelector.setSelectedIndex(2);
        invoke(tab, "refreshServerSelector", new Class<?>[]{});
        invoke(tab, "applyFilter", new Class<?>[]{});
        assertEquals(1, table.visibleOperations().size());
        assertEquals("/orders", table.visibleOperations().get(0).path());
    }

    @Test
    void extractHelpersReturnSafeDefaultsWhenDataMissing() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(null);
        when(requestResponse.response()).thenReturn(null);

        String extractedUrl = (String) invoke(tab, "extractRequestUrl", new Class<?>[]{HttpRequestResponse.class}, requestResponse);
        String extractedBody = (String) invoke(tab, "extractResponseBody", new Class<?>[]{HttpRequestResponse.class}, requestResponse);

        assertEquals("", extractedUrl);
        assertEquals("", extractedBody);

        String selectedServer = (String) invoke(tab, "selectedServer", new Class<?>[]{});
        assertEquals("(Operation default)", selectedServer);
    }

    @Test
    void uiStateIsPersistedAndRestored() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab first = new OpenApiSamplerTab(ctx.api);

        JTextField urlField = (JTextField) field(first, "urlField");
        JTextField filterField = (JTextField) field(first, "filterField");
        @SuppressWarnings("unchecked")
        JComboBox<String> selector = (JComboBox<String>) field(first, "serverSelector");

        urlField.setText("https://state.example/openapi.json");
        filterField.setText("users");
        selector.setSelectedItem("(Operation default)");
        invoke(first, "persistUiState", new Class<?>[]{});
        assertEquals("https://state.example/openapi.json", ctx.extensionData.getString("ui.urlField"));
        assertEquals("users", ctx.extensionData.getString("ui.filterField"));
        assertEquals("", ctx.extensionData.getString("ui.source"));

        OpenApiSamplerTab restored = new OpenApiSamplerTab(ctx.api);
        JTextField restoredUrl = (JTextField) field(restored, "urlField");
        JTextField restoredFilter = (JTextField) field(restored, "filterField");

        assertEquals("https://state.example/openapi.json", restoredUrl.getText());
        assertTrue(restoredFilter.getText().isEmpty() || "users".equals(restoredFilter.getText()));
    }

    @Test
    void authSecretIsNeverPersistedAndIsScrubbed() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        JTextField authKeyField = (JTextField) field(tab, "authKeyField");
        JTextField authValueField = (JTextField) field(tab, "authValueField");

        // Simulate a secret already written to the (unencrypted) project store by an older version.
        ctx.extensionData.setString("ui.authValue", "super-secret-token");
        authKeyField.setText("X-API-Key");
        authValueField.setText("super-secret-token");

        invoke(tab, "persistUiState", new Class<?>[]{});

        // Non-secret prefs are kept; the secret value is never written and any old value is scrubbed.
        assertEquals("X-API-Key", ctx.extensionData.getString("ui.authKey"));
        assertNull(ctx.extensionData.getString("ui.authValue"));
    }

    @Test
    void exportDocumentIncludesSourceAndAllFormats() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://export.example", "/users"), "https://export.example/openapi.json", "export-source");

        invoke(tab, "refreshSourceSelector", new Class<?>[]{});
        invoke(tab, "refreshServerSelector", new Class<?>[]{});
        invoke(tab, "applyFilter", new Class<?>[]{});

        @SuppressWarnings("unchecked")
        Object export = invoke(
                tab,
                "buildExportDocument",
                new Class<?>[]{List.class},
                List.of(model.operations().get(0))
        );

        String content = String.valueOf(recordValue(export, "content"));
        assertTrue(content.contains("Source: export-source"));
        assertTrue(content.contains("[RAW HTTP]"));
        assertTrue(content.contains("[CURL]"));
        assertTrue(content.contains("[PYTHON REQUESTS]"));
    }

    @Test
    void retryableFetchErrorDetectionWorks() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        boolean timeout = (boolean) invoke(tab, "isRetryableFetchError", new Class<?>[]{IOException.class}, new IOException("connection timeout"));
        boolean tooMany = (boolean) invoke(tab, "isRetryableFetchError", new Class<?>[]{IOException.class}, new IOException("HTTP 429 returned"));
        boolean canceled = (boolean) invoke(tab, "isRetryableFetchError", new Class<?>[]{IOException.class}, new IOException("Canceled by user"));
        boolean badRequest = (boolean) invoke(tab, "isRetryableFetchError", new Class<?>[]{IOException.class}, new IOException("HTTP 400 returned"));

        assertTrue(timeout);
        assertTrue(tooMany);
        assertFalse(canceled);
        assertFalse(badRequest);
    }

    @Test
    void specDiscoveryDoesNotFollowCrossHostReferences() throws Exception
    {
        AtomicBoolean crossHostFetched = new AtomicBoolean(false);
        OpenApiSamplerTab tab = new OpenApiSamplerTab(
                TestApiFactory.apiContext().api,
                (url, responseTimeoutMs, perAttemptDeadlineMs, followRedirects) -> {
                    if (url.contains("b.example"))
                    {
                        crossHostFetched.set(true);
                        return fetchResponse(minimalJsonSpec("Cross", "/cross"));
                    }
                    // A Swagger UI page on the entered host that points its spec at a different host.
                    byte[] html = "<script>SwaggerUIBundle({configUrl:\"https://b.example/openapi.json\"})</script>"
                            .getBytes(StandardCharsets.UTF_8);
                    return new OpenApiSamplerTab.FetchResponse((short) 200, html, "text/html", html.length);
                }
        );

        // Discovery must stay on the entered host, so no a.example spec is found and no b.example fetch happens.
        assertThrows(IllegalStateException.class, () ->
                invoke(tab, "fetchAndParseFromUrl", new Class<?>[]{String.class}, "https://a.example/docs"));
        assertFalse(crossHostFetched.get(), "cross-host spec reference must not be fetched");
    }

    @Test
    void cancelDuringInFlightFetchStopsPromptly() throws Exception
    {
        CountDownLatch fetchStarted = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        OpenApiSamplerTab tab = new OpenApiSamplerTab(
                TestApiFactory.apiContext().api,
                (url, responseTimeoutMs, perAttemptDeadlineMs, followRedirects) -> {
                    fetchStarted.countDown();
                    // Simulate a slow/hung server: the request only ends if explicitly released.
                    releaseFetch.await(10, TimeUnit.SECONDS);
                    return fetchResponse(minimalJsonSpec("Late", "/late"));
                }
        );

        AtomicReference<Throwable> caught = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);
        Thread fetchThread = new Thread(() -> {
            try
            {
                invoke(tab, "fetchUrl", new Class<?>[]{String.class}, "https://hang.example/openapi.json");
            }
            catch (Throwable t)
            {
                caught.set(t);
            }
            finally
            {
                done.countDown();
            }
        });
        fetchThread.setDaemon(true);

        try
        {
            fetchThread.start();
            assertTrue(fetchStarted.await(2, TimeUnit.SECONDS));

            // User clicks "Cancel load" while the request is still in flight.
            setField(tab, "loadingInProgress", true);
            invoke(tab, "requestCancelUrlListLoad", new Class<?>[]{});

            // The in-flight fetch must be abandoned promptly, not blocked for the full deadline.
            assertTrue(done.await(2, TimeUnit.SECONDS), "fetch should stop promptly after cancel");
            assertNotNull(caught.get());
            String message = caught.get().getMessage();
            assertTrue(message != null && message.toLowerCase().contains("cancel"),
                    "expected a cancellation error, got: " + caught.get());
        }
        finally
        {
            releaseFetch.countDown();
        }
    }

    @Test
    void bestDecodedCandidatePrefersReadableCyrillicText() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        String mojibake = "ÐÑÐ¸Ð²ÐµÑ";
        String readable = "Привет";

        @SuppressWarnings("unchecked")
        String best = (String) invoke(
                tab,
                "bestDecodedCandidate",
                new Class<?>[]{List.class, String.class},
                List.of(mojibake, readable),
                mojibake
        );

        assertEquals(readable, best);
    }

    @Test
    void decodeScorePenalizesCp1251Utf8MojibakePattern() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        String mojibake = "РџСЂРёРІРµС‚";
        String readable = "Привет";

        int mojibakeScore = (Integer) invoke(tab, "decodeScore", new Class<?>[]{String.class}, mojibake);
        int readableScore = (Integer) invoke(tab, "decodeScore", new Class<?>[]{String.class}, readable);

        assertTrue(readableScore > mojibakeScore);
    }

    @Test
    void readSpecFileContentHandlesWindows1251RussianSummary() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        Path file = Files.createTempFile("openapi-ru-", ".json");
        try
        {
            String spec = "{\"swagger\":\"2.0\",\"paths\":{\"/x\":{\"get\":{\"summary\":\"Привет\"}}}}";
            Files.write(file, spec.getBytes(Charset.forName("windows-1251")));

            String decoded = (String) invoke(tab, "readSpecFileContent", new Class<?>[]{Path.class}, file);
            assertTrue(decoded.contains("Привет"));
        }
        finally
        {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void authFieldsFollowSelectedAuthType() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        @SuppressWarnings("unchecked")
        JComboBox<?> authSelector = (JComboBox<?>) field(tab, "authSelector");
        JLabel authKeyLabel = (JLabel) field(tab, "authKeyLabel");
        JTextField authKeyField = (JTextField) field(tab, "authKeyField");
        JLabel authValueLabel = (JLabel) field(tab, "authValueLabel");
        JTextField authValueField = (JTextField) field(tab, "authValueField");

        authSelector.setSelectedIndex(0);
        assertFalse(authKeyField.isVisible());
        assertFalse(authValueField.isVisible());

        authSelector.setSelectedIndex(1);
        assertFalse(authKeyField.isVisible());
        assertTrue(authValueField.isVisible());
        assertEquals("Token:", authValueLabel.getText());

        authSelector.setSelectedIndex(2);
        assertTrue(authKeyField.isVisible());
        assertTrue(authValueField.isVisible());
        assertEquals("Username:", authKeyLabel.getText());
        assertEquals("Password:", authValueLabel.getText());

        authSelector.setSelectedIndex(3);
        assertEquals("Header name:", authKeyLabel.getText());

        authSelector.setSelectedIndex(4);
        assertEquals("Query name:", authKeyLabel.getText());
    }

    @Test
    void scopeIsNeverModifiedWhenSendingToScan() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit audit = mock(Audit.class);
        CountDownLatch latch = new CountDownLatch(1);
        when(ctx.scanner.startAudit(any())).thenReturn(audit);
        when(audit.statusMessage()).thenReturn("running");
        when(audit.requestCount()).thenReturn(0);
        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(audit).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(latch.await(2, TimeUnit.SECONDS));

        // N1: the extension must never silently change the user's Burp scope.
        verify(ctx.scope, never()).includeInScope(any(String.class));
        verify(ctx.scope, never()).isInScope(any(String.class));
    }

    @Test
    void urlListLineParsingSupportsCommentsCsvAndBareHosts() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        Object blank = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "   ");
        assertFalse((Boolean) recordValue(blank, "accepted"));

        Object comment = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "#comment");
        assertFalse((Boolean) recordValue(comment, "accepted"));

        Object direct = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "https://api.example/openapi.json");
        assertTrue((Boolean) recordValue(direct, "accepted"));
        assertEquals("https://api.example/openapi.json", recordValue(direct, "url"));
        assertFalse((Boolean) recordValue(direct, "normalized"));

        Object csv = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "svc, https://api.csv.example/openapi.json, note");
        assertTrue((Boolean) recordValue(csv, "accepted"));
        assertEquals("https://api.csv.example/openapi.json", recordValue(csv, "url"));
        assertTrue((Boolean) recordValue(csv, "normalized"));

        Object bare = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "api.no-scheme.example/openapi.yaml");
        assertTrue((Boolean) recordValue(bare, "accepted"));
        assertEquals("https://api.no-scheme.example/openapi.yaml", recordValue(bare, "url"));
        assertTrue((Boolean) recordValue(bare, "normalized"));

        Object invalid = invoke(tab, "parseUrlLine", new Class<?>[]{String.class}, "/v3/api-docs");
        assertFalse((Boolean) recordValue(invalid, "accepted"));
    }

    @Test
    void urlListParsingDeduplicatesAndCounts() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);
        @SuppressWarnings("unchecked")
        Object parsed = invoke(tab, "parseUrlList", new Class<?>[]{List.class}, List.of(
                "",
                "# comment",
                "https://api.example/openapi.json",
                "api.example/openapi.json",
                "svc,https://api.example/openapi.json,note",
                "bad"
        ));

        @SuppressWarnings("unchecked")
        List<String> urls = (List<String>) recordValue(parsed, "urls");
        assertEquals(1, urls.size());
        assertEquals("https://api.example/openapi.json", urls.get(0));
        assertEquals(6, recordValue(parsed, "totalLines"));
        assertEquals(2, recordValue(parsed, "normalizedCount"));

        @SuppressWarnings("unchecked")
        List<String> skipNotes = (List<String>) recordValue(parsed, "skipNotes");
        assertEquals(3, skipNotes.size());
    }

    @Test
    void urlListLoadPublishesParsedSpecsIncrementally() throws Exception
    {
        CountDownLatch secondFetchStarted = new CountDownLatch(1);
        CountDownLatch releaseSecondFetch = new CountDownLatch(1);
        OpenApiSamplerTab tab = new OpenApiSamplerTab(
                TestApiFactory.apiContext().api,
                (url, responseTimeoutMs, perAttemptDeadlineMs, followRedirects) -> {
                    if (url.contains("two.example"))
                    {
                        secondFetchStarted.countDown();
                        assertTrue(releaseSecondFetch.await(2, TimeUnit.SECONDS));
                        return fetchResponse(minimalJsonSpec("Two", "/two"));
                    }
                    return fetchResponse(minimalJsonSpec("One", "/one"));
                }
        );
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        Path urlList = Files.createTempFile("openapi-url-list-", ".txt");
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try
        {
            Files.writeString(urlList, """
                    https://one.example/openapi.json
                    https://two.example/openapi.json
                    """);

            Future<Object> result = executor.submit(() -> {
                try
                {
                    return invoke(tab, "fetchAndParseFromUrlList", new Class<?>[]{Path.class}, urlList);
                }
                catch (Exception ex)
                {
                    throw new RuntimeException(ex);
                }
            });

            assertTrue(secondFetchStarted.await(2, TimeUnit.SECONDS));
            assertTrue(waitUntil(() -> model.operations().size() == 1));
            assertEquals("/one", model.operations().get(0).path());

            releaseSecondFetch.countDown();
            Object summary = result.get(2, TimeUnit.SECONDS);
            assertEquals(2, recordValue(summary, "loadedSpecs"));
            assertEquals(2, model.operations().size());
        }
        finally
        {
            releaseSecondFetch.countDown();
            executor.shutdownNow();
            Files.deleteIfExists(urlList);
        }
    }

    @Test
    void buildCandidateSpecUrlsAddsSwaggerFallbackEndpoints() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        @SuppressWarnings("unchecked")
        List<String> candidates = (List<String>) invoke(
                tab,
                "buildCandidateSpecUrls",
                new Class<?>[]{String.class},
                "https://api.example.com/swagger/index.html"
        );

        assertTrue(candidates.contains("https://api.example.com/swagger/index.html"));
        assertTrue(candidates.contains("https://api.example.com/v3/api-docs"));
        assertTrue(candidates.contains("https://api.example.com/v2/api-docs"));
        assertTrue(candidates.contains("https://api.example.com/openapi.json"));
        assertTrue(candidates.contains("https://api.example.com/swagger/v1/swagger.json"));
    }

    @Test
    void buildCandidateSpecUrlsReadsQueryUrlAndConfigUrl() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        @SuppressWarnings("unchecked")
        List<String> candidates = (List<String>) invoke(
                tab,
                "buildCandidateSpecUrls",
                new Class<?>[]{String.class},
                "https://docs.example.com/swagger/index.html?url=%2Fv3%2Fapi-docs&configUrl=%2Fv3%2Fapi-docs%2Fswagger-config"
        );

        assertTrue(candidates.contains("https://docs.example.com/v3/api-docs"));
        assertTrue(candidates.contains("https://docs.example.com/v3/api-docs/swagger-config"));
    }

    @Test
    void extractReferencedUrlsFindsSwaggerUiUrlFields() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        String html = """
                <script>
                  window.ui = SwaggerUIBundle({
                    url: "/v3/api-docs",
                    configUrl: "/v3/api-docs/swagger-config",
                    urls: [{ url: "https://alt.example.com/openapi.json", name: "alt" }]
                  });
                </script>
                """;

        @SuppressWarnings("unchecked")
        List<String> discovered = (List<String>) invoke(
                tab,
                "extractReferencedUrls",
                new Class<?>[]{String.class, String.class},
                "https://docs.example.com/swagger/index.html",
                html
        );

        assertTrue(discovered.contains("https://docs.example.com/v3/api-docs"));
        assertTrue(discovered.contains("https://docs.example.com/v3/api-docs/swagger-config"));
        assertTrue(discovered.contains("https://alt.example.com/openapi.json"));
    }

    @Test
    void sendAllVisibleActionQueuesAllVisibleRowsToRepeater() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");

        model.load(spec("https://one.example", "/users"), "https://one.example/openapi.json");
        model.load(spec("https://two.example", "/orders"), "https://two.example/openapi.json");
        invoke(tab, "refreshServerSelector", new Class<?>[]{});
        invoke(tab, "applyFilter", new Class<?>[]{});

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_VISIBLE_TO_REPEATER,
                List.of()
        );

        Repeater repeater = ctx.repeater;
        verify(repeater, timeout(2000).times(2)).sendToRepeater(any(HttpRequest.class), contains("OpenAPI Sampler / All /"));
    }

    @Test
    void selectedActionQueuesRequestToIntruder() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://intruder.example", "/users"), "https://intruder.example/openapi.json");

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_INTRUDER,
                List.of(model.operations().get(0))
        );

        verify(ctx.intruder, timeout(2000).times(1)).sendToIntruder(any(HttpRequest.class));
    }

    @Test
    void scanTaskIsCreatedFreshForEachSendSoDeletedTasksAreReplaced() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit firstTask = mock(Audit.class);
        Audit secondTask = mock(Audit.class);
        CountDownLatch firstLatch = new CountDownLatch(1);
        CountDownLatch secondLatch = new CountDownLatch(1);
        when(ctx.scanner.startAudit(any())).thenReturn(firstTask, secondTask);
        // After the user deletes a scan task in Burp, the cached Audit handle stays "silent":
        // statusMessage()/requestCount() do not throw and addRequest() becomes a no-op. The old
        // code reused that dead handle and the second send vanished with no scanner progress.
        when(firstTask.statusMessage()).thenReturn("running");
        when(firstTask.requestCount()).thenReturn(0);
        when(secondTask.statusMessage()).thenReturn("running");
        when(secondTask.requestCount()).thenReturn(0);
        doAnswer(invocation -> {
            firstLatch.countDown();
            return null;
        }).when(firstTask).addRequest(any(HttpRequest.class));
        doAnswer(invocation -> {
            secondLatch.countDown();
            return null;
        }).when(secondTask).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(firstLatch.await(2, TimeUnit.SECONDS));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(secondLatch.await(2, TimeUnit.SECONDS));

        verify(ctx.scanner, times(2)).startAudit(any());
        verify(firstTask, times(1)).addRequest(any(HttpRequest.class));
        verify(secondTask, times(1)).addRequest(any(HttpRequest.class));
    }

    @Test
    void activeScanTaskIsRecreatedWhenCachedTaskIsUnavailableBeforeQueue() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit firstAudit = mock(Audit.class);
        Audit secondAudit = mock(Audit.class);
        CountDownLatch firstLatch = new CountDownLatch(1);
        CountDownLatch secondLatch = new CountDownLatch(1);
        when(ctx.scanner.startAudit(any())).thenReturn(firstAudit, secondAudit);
        when(firstAudit.statusMessage()).thenThrow(new RuntimeException("task removed"));
        when(secondAudit.statusMessage()).thenReturn("running");
        when(secondAudit.requestCount()).thenReturn(0);

        doAnswer(invocation -> {
            firstLatch.countDown();
            return null;
        }).when(firstAudit).addRequest(any(HttpRequest.class));
        doAnswer(invocation -> {
            secondLatch.countDown();
            return null;
        }).when(secondAudit).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(firstLatch.await(2, TimeUnit.SECONDS));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );

        assertTrue(secondLatch.await(2, TimeUnit.SECONDS));
        verify(ctx.scanner, times(2)).startAudit(any());
        verify(firstAudit, times(1)).addRequest(any(HttpRequest.class));
        verify(secondAudit, times(1)).addRequest(any(HttpRequest.class));
    }

    @Test
    void addRequestFailureWithUnavailableTaskRecreatesAndRetries() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit firstAudit = mock(Audit.class);
        Audit secondAudit = mock(Audit.class);
        CountDownLatch latch = new CountDownLatch(1);

        when(ctx.scanner.startAudit(any())).thenReturn(firstAudit, secondAudit);
        doAnswer(invocation -> {
            throw new RuntimeException("add failed");
        }).when(firstAudit).addRequest(any(HttpRequest.class));
        when(firstAudit.statusMessage()).thenThrow(new RuntimeException("task deleted"));
        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(secondAudit).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );

        assertTrue(latch.await(2, TimeUnit.SECONDS));
        assertTrue(waitForStatus(tab, text -> text.contains("recreated=1") && text.contains("retried=1")));
        verify(ctx.scanner, times(2)).startAudit(any());
        verify(firstAudit, times(1)).addRequest(any(HttpRequest.class));
        verify(secondAudit, times(1)).addRequest(any(HttpRequest.class));
    }

    @Test
    void addRequestFailureWithUsableTaskDoesNotRecreateAndCountsFailure() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit audit = mock(Audit.class);
        CountDownLatch latch = new CountDownLatch(1);
        when(ctx.scanner.startAudit(any())).thenReturn(audit);
        doAnswer(invocation -> {
            latch.countDown();
            throw new RuntimeException("add failed");
        }).when(audit).addRequest(any(HttpRequest.class));
        when(audit.statusMessage()).thenReturn("running");
        when(audit.requestCount()).thenReturn(0);

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );

        assertTrue(latch.await(2, TimeUnit.SECONDS));
        assertTrue(waitForStatus(tab, text -> text.contains("failed=1") && text.contains("recreated=0")));
        verify(ctx.scanner, times(1)).startAudit(any());
        verify(audit, times(1)).addRequest(any(HttpRequest.class));
    }

    @Test
    void activeAndPassiveScanTasksAreIndependent() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");

        Audit activeAudit = mock(Audit.class);
        Audit passiveAudit = mock(Audit.class);
        CountDownLatch activeLatch = new CountDownLatch(1);
        CountDownLatch passiveLatch = new CountDownLatch(1);

        when(ctx.scanner.startAudit(any())).thenReturn(activeAudit, passiveAudit);
        when(activeAudit.statusMessage()).thenReturn("running");
        when(activeAudit.requestCount()).thenReturn(0);
        when(passiveAudit.statusMessage()).thenReturn("running");
        when(passiveAudit.requestCount()).thenReturn(0);
        doAnswer(invocation -> {
            activeLatch.countDown();
            return null;
        }).when(activeAudit).addRequest(any(HttpRequest.class));
        doAnswer(invocation -> {
            passiveLatch.countDown();
            return null;
        }).when(passiveAudit).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(activeLatch.await(2, TimeUnit.SECONDS));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_PASSIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(passiveLatch.await(2, TimeUnit.SECONDS));

        verify(ctx.scanner, times(2)).startAudit(any());
        verify(activeAudit, times(1)).addRequest(any(HttpRequest.class));
        verify(passiveAudit, times(1)).addRequest(any(HttpRequest.class));
    }

    @Test
    void disposeShutsDownExecutorAndLeavesScanTasksIntact() throws Exception
    {
        TestApiFactory.ApiContext ctx = TestApiFactory.apiContext();
        OpenApiSamplerTab tab = new OpenApiSamplerTab(ctx.api);
        OpenApiSamplerModel model = (OpenApiSamplerModel) field(tab, "model");
        model.load(spec("https://scan.example", "/users"), "https://scan.example/openapi.json");
        ExecutorService workerPool = (ExecutorService) field(tab, "workerPool");

        Audit audit = mock(Audit.class);
        CountDownLatch latch = new CountDownLatch(1);
        when(ctx.scanner.startAudit(any())).thenReturn(audit);
        when(audit.statusMessage()).thenReturn("running");
        when(audit.requestCount()).thenReturn(0);
        doAnswer(invocation -> {
            latch.countDown();
            return null;
        }).when(audit).addRequest(any(HttpRequest.class));

        invoke(
                tab,
                "onSelectionAction",
                new Class<?>[]{OpenApiSamplerTable.SelectionAction.class, List.class},
                OpenApiSamplerTable.SelectionAction.SEND_SELECTED_TO_ACTIVE_SCAN,
                List.of(model.operations().get(0))
        );
        assertTrue(latch.await(2, TimeUnit.SECONDS));

        tab.dispose();
        tab.dispose();

        assertTrue(workerPool.isShutdown());
        // Unloading the extension must not destroy the user's scan task (it holds scan results).
        verify(audit, never()).delete();
    }

    @Test
    void urlListConcurrencyLimitIsOne() throws Exception
    {
        Field limitField = OpenApiSamplerTab.class.getDeclaredField("MAX_CONCURRENT_URL_FETCHES");
        limitField.setAccessible(true);
        int value = limitField.getInt(null);
        assertEquals(1, value);
    }

    @Test
    void bundledOfflineSamplesCanBeParsedFromLocalFiles() throws Exception
    {
        OpenApiSamplerTab tab = new OpenApiSamplerTab(TestApiFactory.apiContext().api);

        Path sample30 = Files.createTempFile("openapi-3.0-local-", ".json");
        Path sample31 = Path.of("samples/openapi-3.1-discriminator.yaml");
        Path sample20 = Path.of("samples/openapi-2.0-basic.yaml");
        try
        {
            Files.writeString(sample30, """
                    {
                      "openapi":"3.0.3",
                      "info":{"title":"Local JSON 3.0","version":"1.0"},
                      "paths":{
                        "/local":{
                          "get":{
                            "responses":{"200":{"description":"ok"}}
                          }
                        }
                      }
                    }
                    """);
            assertTrue(Files.exists(sample31));
            assertTrue(Files.exists(sample20));

            Object outcome30 = invoke(
                    tab,
                    "parseSpec",
                    new Class<?>[]{String.class, String.class, String.class, boolean.class},
                    Files.readString(sample30),
                    sample30.getFileName().toString(),
                    sample30.toUri().toString(),
                    true
            );
            OpenAPI openApi30 = (OpenAPI) recordValue(outcome30, "openAPI");
            assertEquals("3.0.3", openApi30.getOpenapi());
            assertEquals("Local JSON 3.0", openApi30.getInfo().getTitle());

            String sample31Content = Files.readString(sample31);
            String sample20Content = Files.readString(sample20);

            Object outcome31 = invoke(
                    tab,
                    "parseSpec",
                    new Class<?>[]{String.class, String.class, String.class, boolean.class},
                    sample31Content,
                    sample31.getFileName().toString(),
                    sample31.toUri().toString(),
                    true
            );
            OpenAPI openApi31 = (OpenAPI) recordValue(outcome31, "openAPI");
            assertEquals("3.1.0", openApi31.getOpenapi());
            assertEquals("OpenAPI Sampler Demo 3.1", openApi31.getInfo().getTitle());
            assertTrue(sample20Content.contains("swagger: '2.0'"));
            assertTrue(Utils.looksLikeOpenApiSpec(sample20Content));
        }
        finally
        {
            Files.deleteIfExists(sample30);
        }
    }

    @Test
    void topBulkButtonsAreRemovedFromTabFields()
    {
        assertThrows(NoSuchFieldException.class, () -> OpenApiSamplerTab.class.getDeclaredField("generateAllButton"));
        assertThrows(NoSuchFieldException.class, () -> OpenApiSamplerTab.class.getDeclaredField("deleteSelectedButton"));
        assertThrows(NoSuchFieldException.class, () -> OpenApiSamplerTab.class.getDeclaredField("repeaterSelectedButton"));
        assertThrows(NoSuchFieldException.class, () -> OpenApiSamplerTab.class.getDeclaredField("intruderSelectedButton"));
    }

    private OpenAPI spec(String server, String path)
    {
        return new OpenAPI()
                .servers(List.of(new Server().url(server)))
                .paths(new Paths().addPathItem(path, new PathItem().get(new Operation().summary(path))));
    }

    private Object field(Object target, String fieldName) throws Exception
    {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(target);
    }

    private void setField(Object target, String fieldName, Object value) throws Exception
    {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private Object invoke(Object target, String methodName, Class<?>[] types, Object... args) throws Exception
    {
        Method method = target.getClass().getDeclaredMethod(methodName, types);
        method.setAccessible(true);
        try
        {
            return method.invoke(target, args);
        }
        catch (java.lang.reflect.InvocationTargetException ex)
        {
            Throwable cause = ex.getCause();
            if (cause instanceof Exception exception)
            {
                throw exception;
            }
            throw ex;
        }
    }

    private Object recordValue(Object record, String accessor) throws Exception
    {
        Method accessorMethod = record.getClass().getDeclaredMethod(accessor);
        accessorMethod.setAccessible(true);
        return accessorMethod.invoke(record);
    }

    private boolean waitForStatus(OpenApiSamplerTab tab, Predicate<String> predicate) throws Exception
    {
        long deadline = System.currentTimeMillis() + 2_000L;
        JLabelHolder labelHolder = new JLabelHolder((javax.swing.JLabel) field(tab, "statusLabel"));
        while (System.currentTimeMillis() < deadline)
        {
            String text = labelHolder.text();
            if (predicate.test(text))
            {
                return true;
            }
            Thread.sleep(20L);
        }
        return predicate.test(labelHolder.text());
    }

    private boolean waitUntil(java.util.function.BooleanSupplier condition) throws Exception
    {
        long deadline = System.currentTimeMillis() + 2_000L;
        while (System.currentTimeMillis() < deadline)
        {
            if (condition.getAsBoolean())
            {
                return true;
            }
            Thread.sleep(20L);
        }
        return condition.getAsBoolean();
    }

    private OpenApiSamplerTab.FetchResponse fetchResponse(String body)
    {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return new OpenApiSamplerTab.FetchResponse((short) 200, bytes, "application/json", bytes.length);
    }

    private String minimalJsonSpec(String title, String path)
    {
        return """
                {
                  "openapi":"3.0.3",
                  "info":{"title":"%s","version":"1.0"},
                  "paths":{
                    "%s":{
                      "get":{
                        "responses":{"200":{"description":"ok"}}
                      }
                    }
                  }
                }
                """.formatted(title, path);
    }

    private static final class JLabelHolder
    {
        private final javax.swing.JLabel label;

        private JLabelHolder(javax.swing.JLabel label)
        {
            this.label = label;
        }

        private String text()
        {
            String text = label.getText();
            return text == null ? "" : text;
        }
    }
}
