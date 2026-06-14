package burp.openapi;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.mozilla.universalchardet.UniversalDetector;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main UI tab and behavior controller.
 */
public final class OpenApiSamplerTab implements ContextMenuItemsProvider
{
    private static final String TAB_TITLE = "OpenAPI Sampler";
    private static final String EXTENSION_PREFIX = "[OpenAPI Sampler] ";
    private static final String DEFAULT_SERVER_ITEM = "(Operation default)";
    private static final String DEFAULT_SOURCE_ITEM = "(All sources)";
    private static final int MAX_SPEC_FETCH_ATTEMPTS = 24;
    private static final int MAX_FETCH_RETRIES = 3;
    private static final int FETCH_RETRY_BACKOFF_MS = 250;
    private static final int MAX_CONCURRENT_URL_FETCHES = 1;
    private static final long RESPONSE_TIMEOUT_MS = 25_000L;
    private static final long PER_ATTEMPT_DEADLINE_MS = 30_000L;
    private static final long CANCEL_POLL_INTERVAL_MS = 150L;
    private static final int MAX_SPEC_SIZE_BYTES = 5 * 1024 * 1024;
    private static final String STATE_URL_FIELD = "ui.urlField";
    private static final String STATE_FILTER_FIELD = "ui.filterField";
    private static final String STATE_SERVER = "ui.server";
    private static final String STATE_SOURCE = "ui.source";
    private static final String STATE_AUTH_TYPE = "ui.authType";
    private static final String STATE_AUTH_KEY = "ui.authKey";
    private static final String STATE_AUTH_VALUE = "ui.authValue";
    private static final String STATE_SOURCES = "ui.sources";
    private static final int FILTER_DEBOUNCE_MS = 180;
    private static final Pattern URL_FIELD_PATTERN = Pattern.compile(
            "(?i)(?:\\burl\\b|\\bconfigUrl\\b|[\"']url[\"']|[\"']configUrl[\"'])\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    private static final Pattern CHARSET_PATTERN = Pattern.compile("(?i)charset\\s*=\\s*([a-z0-9._-]+)");
    private static final Pattern CP1251_MOJIBAKE_PATTERN = Pattern.compile("(?:Р[\\u0400-\\u04FF]|С[\\u0400-\\u04FF]){3,}");

    private final MontoyaApi api;
    private final JPanel rootPanel;
    private final OpenApiSamplerModel model;
    private final OpenApiSamplerTable table;
    private final RequestGenerator requestGenerator;
    private final ExecutorService workerPool;
    private final SpecFetcher specFetcher;

    private final JButton loadFileButton;
    private final JButton loadUrlListButton;
    private final JButton fetchButton;
    private final JButton cancelLoadButton;
    private final JButton copyFailedButton;
    private final JButton clearFailedButton;
    private final JTextField urlField;
    private final JTextField filterField;
    private final JComboBox<SourceSelection> sourceSelector;
    private final JComboBox<String> serverSelector;
    private final JComboBox<AuthSelection> authSelector;
    private final JLabel authKeyLabel;
    private final JTextField authKeyField;
    private final JLabel authValueLabel;
    private final JTextField authValueField;
    private final JLabel statusLabel;
    private final JLabel progressLabel;
    private final JLabel requestPreviewLabel;
    private final HttpRequestEditor requestPreviewEditor;
    private final JLabel responsePreviewLabel;
    private final HttpResponseEditor responsePreviewEditor;
    private final JLabel failedSummaryLabel;
    private final List<String> lastLoadFailures = new CopyOnWriteArrayList<>();
    private final AtomicBoolean disposed = new AtomicBoolean(false);
    private final Timer filterDebounceTimer;

    private volatile boolean loadingInProgress;
    private volatile boolean cancelRequested;
    private String restoredSourceId = "";
    private String restoredServer = "";
    private List<String> restoredSourceLocations = List.of();

    public OpenApiSamplerTab(MontoyaApi api)
    {
        this(api, null);
    }

    OpenApiSamplerTab(MontoyaApi api, SpecFetcher specFetcher)
    {
        this.api = Objects.requireNonNull(api, "api must not be null");
        this.model = new OpenApiSamplerModel();
        this.table = new OpenApiSamplerTable();
        this.requestGenerator = new RequestGenerator();
        this.specFetcher = specFetcher != null ? specFetcher : this::fetchViaMontoya;
        this.workerPool = Executors.newFixedThreadPool(2, runnable -> {
            Thread worker = new Thread(runnable, "openapi-sampler-worker");
            worker.setDaemon(true);
            return worker;
        });

        this.rootPanel = new JPanel(new BorderLayout(8, 8));
        this.rootPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        this.loadFileButton = new JButton("Load from file");
        this.loadUrlListButton = new JButton("Load URL list");
        this.urlField = new JTextField(48);
        this.fetchButton = new JButton("Fetch");
        this.cancelLoadButton = new JButton("Cancel load");
        this.cancelLoadButton.setEnabled(false);

        this.sourceSelector = new JComboBox<>();
        this.sourceSelector.addItem(SourceSelection.allSources());
        this.serverSelector = new JComboBox<>();
        this.serverSelector.addItem(DEFAULT_SERVER_ITEM);
        this.authSelector = new JComboBox<>();
        this.authSelector.addItem(AuthSelection.none());
        this.authSelector.addItem(AuthSelection.bearer());
        this.authSelector.addItem(AuthSelection.basic());
        this.authSelector.addItem(AuthSelection.apiKeyHeader());
        this.authSelector.addItem(AuthSelection.apiKeyQuery());
        this.authSelector.addItem(AuthSelection.oauth2Bearer());
        this.authKeyLabel = new JLabel("Key:");
        this.authKeyField = new JTextField(14);
        this.authValueLabel = new JLabel("Value:");
        this.authValueField = new JTextField(20);

        this.filterField = new JTextField(32);

        this.statusLabel = new JLabel("Load an OpenAPI specification to begin.");
        this.progressLabel = new JLabel("Progress: idle");
        this.requestPreviewLabel = new JLabel("Request preview: select an operation.");
        this.requestPreviewEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.requestPreviewEditor.setRequest(previewPlaceholderRequest());
        this.responsePreviewLabel = new JLabel("Response preview: select an operation.");
        this.responsePreviewEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        this.responsePreviewEditor.setResponse(previewPlaceholderResponse());
        this.failedSummaryLabel = new JLabel("Load errors: none.");
        this.copyFailedButton = new JButton("Copy failed URLs");
        this.copyFailedButton.setEnabled(false);
        this.clearFailedButton = new JButton("Clear errors");
        this.clearFailedButton.setEnabled(false);
        this.filterDebounceTimer = new Timer(FILTER_DEBOUNCE_MS, e -> applyFilter());
        this.filterDebounceTimer.setRepeats(false);

        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        JPanel loadRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        loadRow.add(loadFileButton);
        loadRow.add(loadUrlListButton);
        loadRow.add(new JLabel("Load from URL:"));
        loadRow.add(urlField);
        loadRow.add(fetchButton);
        loadRow.add(cancelLoadButton);

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        optionsRow.add(new JLabel("Source:"));
        optionsRow.add(sourceSelector);
        optionsRow.add(new JLabel("Server:"));
        optionsRow.add(serverSelector);
        optionsRow.add(new JLabel("Filter:"));
        optionsRow.add(filterField);

        JPanel authRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        authRow.add(new JLabel("Auth:"));
        authRow.add(authSelector);
        authRow.add(authKeyLabel);
        authRow.add(authKeyField);
        authRow.add(authValueLabel);
        authRow.add(authValueField);

        controls.add(loadRow);
        controls.add(optionsRow);
        controls.add(authRow);

        JPanel previewPanel = new JPanel(new BorderLayout(6, 6));
        previewPanel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        JPanel requestPreviewPanel = new JPanel(new BorderLayout(6, 6));
        requestPreviewPanel.add(requestPreviewLabel, BorderLayout.NORTH);
        requestPreviewPanel.add(requestPreviewEditor.uiComponent(), BorderLayout.CENTER);

        JPanel responsePreviewPanel = new JPanel(new BorderLayout(6, 6));
        responsePreviewPanel.add(responsePreviewLabel, BorderLayout.NORTH);
        responsePreviewPanel.add(responsePreviewEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane previewSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPreviewPanel, responsePreviewPanel);
        previewSplitPane.setResizeWeight(0.5d);
        previewSplitPane.setContinuousLayout(true);
        previewPanel.add(previewSplitPane, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, table, previewPanel);
        splitPane.setResizeWeight(0.68d);
        splitPane.setContinuousLayout(true);

        this.rootPanel.add(controls, BorderLayout.NORTH);
        this.rootPanel.add(splitPane, BorderLayout.CENTER);

        table.setRowActionListener(this::onRowAction);
        table.setSelectionActionListener(this::onSelectionAction);
        table.setSelectionChangedListener(this::onTableSelectionChanged);

        loadFileButton.addActionListener(e -> onLoadFromFile());
        loadUrlListButton.addActionListener(e -> onLoadFromUrlListFile());
        fetchButton.addActionListener(e -> fetchAndLoadFromUrl(urlField.getText()));
        cancelLoadButton.addActionListener(e -> requestCancelUrlListLoad());
        copyFailedButton.addActionListener(e -> copyFailedUrlsToClipboard());
        clearFailedButton.addActionListener(e -> clearLoadErrors());
        sourceSelector.addActionListener(e -> {
            refreshServerSelector();
            applyFilter();
            persistUiState();
        });
        serverSelector.addActionListener(e -> {
            applyFilter();
            persistUiState();
        });

        filterField.getDocument().addDocumentListener(new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e)
            {
                scheduleFilterApply();
                persistUiState();
            }

            @Override
            public void removeUpdate(DocumentEvent e)
            {
                scheduleFilterApply();
                persistUiState();
            }

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                scheduleFilterApply();
                persistUiState();
            }
        });

        urlField.getDocument().addDocumentListener(new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e)
            {
                persistUiState();
            }

            @Override
            public void removeUpdate(DocumentEvent e)
            {
                persistUiState();
            }

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                persistUiState();
            }
        });
        authSelector.addActionListener(e -> {
            updateAuthFieldHints();
            persistUiState();
        });
        DocumentListener persistOnlyListener = new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e)
            {
                persistUiState();
            }

            @Override
            public void removeUpdate(DocumentEvent e)
            {
                persistUiState();
            }

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                persistUiState();
            }
        };
        authKeyField.getDocument().addDocumentListener(persistOnlyListener);
        authValueField.getDocument().addDocumentListener(persistOnlyListener);

        restoreUiState();
        updateAuthFieldHints();
        restorePersistedSourcesAsync();
    }

    public String tabTitle()
    {
        return TAB_TITLE;
    }

    public Component uiComponent()
    {
        return rootPanel;
    }

    public void dispose()
    {
        if (!disposed.compareAndSet(false, true))
        {
            return;
        }

        cancelRequested = true;
        loadingInProgress = false;
        filterDebounceTimer.stop();
        // Intentionally do NOT delete the user's scan tasks here: unloading the extension must leave
        // their running/finished Active/Passive scans (and results) intact in the Burp dashboard.
        lastLoadFailures.clear();

        workerPool.shutdown();
        try
        {
            if (!workerPool.awaitTermination(3, TimeUnit.SECONDS))
            {
                workerPool.shutdownNow();
                workerPool.awaitTermination(2, TimeUnit.SECONDS);
            }
        }
        catch (InterruptedException interrupted)
        {
            workerPool.shutdownNow();
            Thread.currentThread().interrupt();
        }

        try
        {
            if (SwingUtilities.isEventDispatchThread())
            {
                clearUiForDispose();
            }
            else
            {
                SwingUtilities.invokeAndWait(this::clearUiForDispose);
            }
        }
        catch (Exception ignored)
        {
            // Best-effort cleanup; unload should proceed even if UI teardown fails.
        }
    }

    private void clearUiForDispose()
    {
        table.dispose();
        model.clear();
        sourceSelector.removeAllItems();
        serverSelector.removeAllItems();
        authSelector.removeAllItems();
        authKeyField.setText("");
        authValueField.setText("");
        filterField.setText("");
        urlField.setText("");
        requestPreviewEditor.setRequest(previewPlaceholderRequest());
        responsePreviewEditor.setResponse(previewPlaceholderResponse());
        statusLabel.setText("Extension unloaded.");
        progressLabel.setText("Progress: unloaded");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event == null)
        {
            return Collections.emptyList();
        }

        if (!event.isFromTool(ToolType.TARGET))
        {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty())
        {
            return Collections.emptyList();
        }

        HttpRequestResponse first = selected.get(0);
        String requestUrl = extractRequestUrl(first);
        String responseBody = extractResponseBody(first);

        boolean hasOpenApiUrl = Utils.looksLikeOpenApiUrl(requestUrl);
        boolean hasOpenApiBody = Utils.looksLikeOpenApiSpec(responseBody);

        if (!hasOpenApiUrl && !hasOpenApiBody)
        {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem("Send to OpenAPI Sampler");
        menuItem.addActionListener(e -> {
            if (hasOpenApiBody)
            {
                parseAndDisplaySpecAsync(responseBody, "context response", requestUrl, false, "Parsing context response...");
                return;
            }

            if (hasOpenApiUrl)
            {
                urlField.setText(requestUrl);
                fetchAndLoadFromUrl(requestUrl);
            }
        });

        return List.of(menuItem);
    }

    private void onLoadFromFile()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select OpenAPI / Swagger file");
        chooser.setFileFilter(new FileNameExtensionFilter("OpenAPI files (*.json, *.yaml, *.yml)", "json", "yaml", "yml"));

        int result = chooser.showOpenDialog(rootPanel);
        if (result != JFileChooser.APPROVE_OPTION)
        {
            return;
        }

        Path path = chooser.getSelectedFile().toPath();

        runBackgroundLoad("Parsing OpenAPI file...", () -> {
            String content = readSpecFileContent(path);
            return parseSpec(content, path.getFileName().toString(), path.toUri().toString(), true);
        }, "File load");
    }

    private void fetchAndLoadFromUrl(String url)
    {
        if (Utils.isBlank(url))
        {
            showError("Validation error", "Please enter a URL.");
            return;
        }

        final String normalizedUrl = url.trim();
        persistUiState();
        runBackgroundLoad("Fetching OpenAPI from URL...", () -> fetchAndParseFromUrl(normalizedUrl), "Fetch");
    }

    private void onLoadFromUrlListFile()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select file with OpenAPI URLs");
        chooser.setFileFilter(new FileNameExtensionFilter("URL list files (*.txt, *.list, *.urls, *.csv)", "txt", "list", "urls", "csv"));

        int result = chooser.showOpenDialog(rootPanel);
        if (result != JFileChooser.APPROVE_OPTION)
        {
            return;
        }

        Path path = chooser.getSelectedFile().toPath();
        runBackgroundUrlListLoad(path);
    }

    private void runBackgroundUrlListLoad(Path listPath)
    {
        if (disposed.get())
        {
            return;
        }

        if (loadingInProgress)
        {
            statusLabel.setText("OpenAPI loading is already in progress...");
            return;
        }

        clearLoadErrors();
        cancelRequested = false;
        loadingInProgress = true;
        progressLabel.setText("Progress: preparing URL list...");
        setLoadingState(true, "Fetching OpenAPI specs from URL list (max concurrent fetches: "
                + MAX_CONCURRENT_URL_FETCHES + ")...");

        CompletableFuture
                .supplyAsync(() -> {
                    try
                    {
                        return fetchAndParseFromUrlList(listPath);
                    }
                    catch (Exception ex)
                    {
                        throw new CompletionException(ex);
                    }
                }, workerPool)
                .whenComplete((result, throwable) -> SwingUtilities.invokeLater(() -> {
                    if (disposed.get())
                    {
                        return;
                    }
                    loadingInProgress = false;
                    cancelRequested = false;
                    setLoadingState(false, null);

                    if (throwable != null)
                    {
                        Throwable root = unwrap(throwable);
                        progressLabel.setText("Progress: failed");
                        registerLoadFailure("URL list", Utils.coalesce(root.getMessage(), root.getClass().getSimpleName()));
                        logError("URL list load failed: " + root.getMessage(), toException(root));
                        showError("URL list load error", "Unable to complete operation:\n" + root.getMessage());
                        return;
                    }

                    applyUrlListLoadOutcome(result);
                }));
    }

    private UrlListLoadResult fetchAndParseFromUrlList(Path listPath) throws Exception
    {
        UrlListParseResult parsed = parseUrlList(Files.readAllLines(listPath, StandardCharsets.UTF_8));
        if (parsed.urls().isEmpty())
        {
            throw new IllegalStateException("No valid URLs found in file: " + listPath.getFileName());
        }

        publishUrlListProgress(0, parsed.urls().size(), "Starting...");

        if (!parsed.normalizationNotes().isEmpty())
        {
            for (String note : parsed.normalizationNotes())
            {
                log(note);
            }
        }

        if (!parsed.skipNotes().isEmpty())
        {
            int maxPreview = Math.min(8, parsed.skipNotes().size());
            for (int i = 0; i < maxPreview; i++)
            {
                log(parsed.skipNotes().get(i));
            }
            if (parsed.skipNotes().size() > maxPreview)
            {
                log("URL list skipped lines omitted: +" + (parsed.skipNotes().size() - maxPreview));
            }
        }

        List<String> failures = new ArrayList<>();
        int processed = 0;
        int loadedSpecs = 0;
        int addedOperations = 0;
        boolean canceled = false;
        for (String url : parsed.urls())
        {
            if (cancelRequested || disposed.get())
            {
                canceled = true;
                break;
            }

            publishUrlListProgress(processed, parsed.urls().size(), "Fetching " + url);
            try
            {
                ParseOutcome outcome = fetchAndParseFromUrl(url);
                int added = applyParseOutcomeOnEdt(outcome);
                loadedSpecs++;
                addedOperations += added;
            }
            catch (Exception ex)
            {
                if (isCancellationError(ex))
                {
                    canceled = true;
                    break;
                }
                String failure = url + " -> " + Utils.coalesce(ex.getMessage(), ex.getClass().getSimpleName());
                failures.add(failure);
                registerLoadFailure(url, Utils.coalesce(ex.getMessage(), ex.getClass().getSimpleName()));
            }
            processed++;
            publishUrlListProgress(processed, parsed.urls().size(), "Processed " + url);
        }

        return new UrlListLoadResult(
                failures,
                parsed.totalLines(),
                parsed.urls().size(),
                parsed.normalizedCount(),
                parsed.skipNotes().size(),
                listPath.getFileName().toString(),
                processed,
                loadedSpecs,
                addedOperations,
                canceled
        );
    }

    private UrlListParseResult parseUrlList(List<String> lines)
    {
        if (lines == null || lines.isEmpty())
        {
            return new UrlListParseResult(List.of(), List.of(), List.of(), 0, 0);
        }

        List<String> normalizationNotes = new ArrayList<>();
        List<String> skipNotes = new ArrayList<>();
        LinkedHashSet<String> uniqueUrls = new LinkedHashSet<>();
        int normalizedCount = 0;

        for (int i = 0; i < lines.size(); i++)
        {
            int lineNumber = i + 1;
            UrlLineDecision decision = parseUrlLine(lines.get(i));

            if (!decision.accepted())
            {
                skipNotes.add("URL list line " + lineNumber + " skipped: " + decision.note());
                continue;
            }

            if (decision.normalized())
            {
                normalizedCount++;
                normalizationNotes.add("URL list line " + lineNumber + " normalized: " + decision.note());
            }
            uniqueUrls.add(decision.url());
        }

        return new UrlListParseResult(
                List.copyOf(uniqueUrls),
                List.copyOf(normalizationNotes),
                List.copyOf(skipNotes),
                lines.size(),
                normalizedCount
        );
    }

    private UrlLineDecision parseUrlLine(String line)
    {
        String trimmed = Utils.coalesce(line);
        if (Utils.isBlank(trimmed))
        {
            return UrlLineDecision.skipped("blank");
        }
        if (trimmed.startsWith("#"))
        {
            return UrlLineDecision.skipped("comment");
        }

        String direct = normalizeToken(trimmed);
        if (Utils.looksLikeHttpUrl(direct))
        {
            return UrlLineDecision.accepted(direct, false, "direct URL");
        }

        List<String> tokens = csvTokens(trimmed);
        if (!tokens.isEmpty())
        {
            for (String token : tokens)
            {
                String normalized = normalizeToken(token);
                if (Utils.looksLikeHttpUrl(normalized))
                {
                    if (!normalized.equals(direct))
                    {
                        return UrlLineDecision.accepted(normalized, true, "extracted URL token from CSV-like line");
                    }
                    return UrlLineDecision.accepted(normalized, false, "direct URL");
                }
            }

            String firstToken = normalizeToken(tokens.get(0));
            if (looksLikeBareUrlCandidate(firstToken))
            {
                return UrlLineDecision.accepted("https://" + firstToken, true, "added https:// to bare host token");
            }
        }

        if (looksLikeBareUrlCandidate(direct))
        {
            return UrlLineDecision.accepted("https://" + direct, true, "added https:// to bare host");
        }

        return UrlLineDecision.skipped("not a supported URL format");
    }

    private List<String> csvTokens(String line)
    {
        if (Utils.isBlank(line))
        {
            return List.of();
        }
        if (!line.contains(",") && !line.contains(";") && !line.contains("\t"))
        {
            return List.of();
        }

        String[] rawTokens = line.split("[,;\\t]");
        List<String> tokens = new ArrayList<>();
        for (String rawToken : rawTokens)
        {
            String token = normalizeToken(rawToken);
            if (Utils.nonBlank(token))
            {
                tokens.add(token);
            }
        }
        return tokens;
    }

    private String normalizeToken(String value)
    {
        if (value == null)
        {
            return "";
        }

        String normalized = value.trim();
        if ((normalized.startsWith("\"") && normalized.endsWith("\""))
                || (normalized.startsWith("'") && normalized.endsWith("'")))
        {
            if (normalized.length() > 1)
            {
                normalized = normalized.substring(1, normalized.length() - 1);
            }
        }

        int inlineComment = normalized.indexOf(" #");
        if (inlineComment >= 0)
        {
            normalized = normalized.substring(0, inlineComment).trim();
        }

        if (normalized.contains(" "))
        {
            normalized = normalized.split("\\s+")[0];
        }

        return normalized.trim();
    }

    private boolean looksLikeBareUrlCandidate(String value)
    {
        if (Utils.isBlank(value))
        {
            return false;
        }

        String candidate = normalizeToken(value);
        if (Utils.isBlank(candidate))
        {
            return false;
        }
        if (candidate.startsWith("/"))
        {
            return false;
        }
        if (candidate.startsWith("#"))
        {
            return false;
        }
        if (candidate.contains("://"))
        {
            return false;
        }

        String authorityPart = candidate.split("/", 2)[0];
        if (!(authorityPart.contains(".")
                || authorityPart.contains(":")
                || authorityPart.equalsIgnoreCase("localhost")
                || authorityPart.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")
                || authorityPart.startsWith("[")))
        {
            return false;
        }

        try
        {
            URI uri = URI.create("https://" + candidate);
            return Utils.nonBlank(uri.getHost());
        }
        catch (Exception ignored)
        {
            return false;
        }
    }

    private ParseOutcome fetchAndParseFromUrl(String normalizedUrl) throws Exception
    {
        URI.create(normalizedUrl);

        // Spec auto-discovery (Swagger UI configUrl/url fields and ?url= query params) may point to
        // arbitrary hosts. Restrict every discovered candidate to the host the user actually entered,
        // so loading one URL never fans out network traffic to a different host.
        String allowedHost = hostOf(normalizedUrl);

        Deque<String> queue = new ArrayDeque<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (String candidate : buildCandidateSpecUrls(normalizedUrl))
        {
            enqueueSpecCandidate(queue, seen, candidate, allowedHost);
        }

        List<String> attemptErrors = new ArrayList<>();
        int attempts = 0;

        while (!queue.isEmpty() && attempts < MAX_SPEC_FETCH_ATTEMPTS)
        {
            if (cancelRequested || disposed.get())
            {
                throw new IOException("Canceled by user");
            }

            String candidate = queue.removeFirst();
            attempts++;

            try
            {
                HttpFetchResult fetchResult = fetchUrl(candidate);
                String payload = fetchResult.body();

                try
                {
                    ParseOutcome outcome = parseSpec(payload, candidate, candidate, true);
                    if (!normalizedUrl.equals(candidate))
                    {
                        log("Resolved spec URL: " + normalizedUrl + " -> " + candidate);
                    }
                    return outcome;
                }
                catch (Exception parseEx)
                {
                    List<String> discovered = extractReferencedUrls(candidate, payload);
                    int newlyQueued = 0;
                    for (String referenced : discovered)
                    {
                        if (enqueueSpecCandidate(queue, seen, referenced, allowedHost))
                        {
                            newlyQueued++;
                        }
                    }

                    if (newlyQueued > 0)
                    {
                        log("URL candidate " + candidate + " is not a spec; discovered " + newlyQueued + " additional candidate(s).");
                        attemptErrors.add(candidate + " -> parse: discovered " + newlyQueued + " additional URL candidate(s)");
                        continue;
                    }
                    attemptErrors.add(candidate + " -> parse: " + conciseError(parseEx));
                }
            }
            catch (Exception fetchEx)
            {
                attemptErrors.add(candidate + " -> fetch: " + conciseError(fetchEx));
            }
        }

        if (!queue.isEmpty())
        {
            attemptErrors.add("Stopped after " + MAX_SPEC_FETCH_ATTEMPTS + " attempts to prevent infinite candidate loops.");
        }

        StringBuilder message = new StringBuilder("Unable to parse OpenAPI from URL: " + normalizedUrl);
        if (!attemptErrors.isEmpty())
        {
            int preview = Math.min(6, attemptErrors.size());
            message.append("\nTried endpoints:");
            for (int i = 0; i < preview; i++)
            {
                message.append("\n- ").append(attemptErrors.get(i));
            }
            if (attemptErrors.size() > preview)
            {
                message.append("\n- ... +").append(attemptErrors.size() - preview).append(" more");
            }
        }
        throw new IllegalStateException(message.toString());
    }

    private HttpFetchResult fetchUrl(String candidateUrl) throws IOException
    {
        IOException lastError = null;
        for (int attempt = 1; attempt <= MAX_FETCH_RETRIES; attempt++)
        {
            if (cancelRequested)
            {
                throw new IOException("Canceled by user");
            }

            try
            {
                FetchResponse response = fetchWithCancellation(candidateUrl);
                if (response == null)
                {
                    throw new IOException("network: no response received");
                }

                long declaredContentLength = response.contentLength();
                if (declaredContentLength > MAX_SPEC_SIZE_BYTES)
                {
                    throw new IOException("size-limit: declared Content-Length " + declaredContentLength
                            + " exceeds max " + MAX_SPEC_SIZE_BYTES + " bytes");
                }

                byte[] bodyBytes = response.bodyBytes() == null ? new byte[0] : response.bodyBytes();
                if (bodyBytes.length > MAX_SPEC_SIZE_BYTES)
                {
                    throw new IOException("size-limit: response body " + bodyBytes.length
                            + " exceeds max " + MAX_SPEC_SIZE_BYTES + " bytes");
                }

                short statusCode = response.statusCode();
                if (statusCode >= 200 && statusCode <= 299)
                {
                    String decoded = decodeBytesBestEffort(
                            bodyBytes,
                            detectCharsetFromContentTypeValue(response.contentType()),
                            ""
                    );
                    return new HttpFetchResult(candidateUrl, statusCode, decoded);
                }

                if (statusCode >= 500 || statusCode == 429)
                {
                    throw new IOException("non-2xx: HTTP " + statusCode + " returned");
                }

                throw new IOException("non-2xx: HTTP " + statusCode + " returned");
            }
            catch (IOException ioEx)
            {
                lastError = ioEx;
                if (attempt >= MAX_FETCH_RETRIES || !isRetryableFetchError(ioEx))
                {
                    break;
                }

                log("Fetch retry " + attempt + "/" + MAX_FETCH_RETRIES + " for " + candidateUrl + ": " + conciseError(ioEx));
                sleepBackoff(attempt);
            }
            catch (Exception ex)
            {
                lastError = new IOException(Utils.coalesce(ex.getMessage(), ex.getClass().getSimpleName()), ex);
                if (attempt >= MAX_FETCH_RETRIES)
                {
                    break;
                }
                log("Fetch retry " + attempt + "/" + MAX_FETCH_RETRIES + " for " + candidateUrl + ": " + conciseError(lastError));
                sleepBackoff(attempt);
            }
        }

        throw lastError == null ? new IOException("Unknown fetch error") : lastError;
    }

    /**
     * Runs a single fetch on a daemon thread while polling the cancel flag, so that clicking
     * "Cancel load" abandons an in-flight request promptly instead of blocking the worker until
     * the per-attempt deadline (or the server) finally responds.
     */
    private FetchResponse fetchWithCancellation(String candidateUrl) throws Exception
    {
        FutureTask<FetchResponse> fetchTask = new FutureTask<>(() ->
                specFetcher.fetch(candidateUrl, RESPONSE_TIMEOUT_MS, PER_ATTEMPT_DEADLINE_MS, true));
        Thread fetchThread = new Thread(fetchTask, "openapi-sampler-fetch");
        fetchThread.setDaemon(true);
        fetchThread.start();

        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(PER_ATTEMPT_DEADLINE_MS);
        while (true)
        {
            if (cancelRequested || disposed.get())
            {
                fetchTask.cancel(true);
                throw new IOException("Canceled by user");
            }

            try
            {
                return fetchTask.get(CANCEL_POLL_INTERVAL_MS, TimeUnit.MILLISECONDS);
            }
            catch (TimeoutException pollTimeout)
            {
                if (System.nanoTime() >= deadlineNanos)
                {
                    fetchTask.cancel(true);
                    throw new IOException("timeout: attempt deadline exceeded (" + PER_ATTEMPT_DEADLINE_MS + " ms)", pollTimeout);
                }
            }
            catch (InterruptedException interruptedException)
            {
                fetchTask.cancel(true);
                Thread.currentThread().interrupt();
                throw new IOException("timeout: interrupted while waiting for response", interruptedException);
            }
            catch (ExecutionException executionException)
            {
                Throwable cause = executionException.getCause();
                if (cause instanceof Exception ex)
                {
                    throw ex;
                }
                throw new IOException("network: " + executionException.getMessage(), executionException);
            }
        }
    }

    private FetchResponse fetchViaMontoya(
            String candidateUrl,
            long responseTimeoutMs,
            long attemptDeadlineMs,
            boolean followRedirects) throws Exception
    {
        RequestOptions requestOptions = RequestOptions.requestOptions()
                .withResponseTimeout(responseTimeoutMs)
                .withRedirectionMode(followRedirects ? RedirectionMode.ALWAYS : RedirectionMode.NEVER);

        HttpRequest specRequest = HttpRequest.httpRequestFromUrl(candidateUrl)
                .withMethod("GET")
                .withAddedHeader("Accept", "application/json, application/yaml, text/yaml, */*");

        // The cancellation/deadline wrapper (fetchWithCancellation) runs this on a daemon thread and
        // enforces the per-attempt deadline, so the request itself only needs the Montoya response timeout.
        HttpRequestResponse response = api.http().sendRequest(specRequest, requestOptions);

        if (response == null || !response.hasResponse() || response.response() == null)
        {
            throw new IOException("network: no response received");
        }

        HttpResponse httpResponse = response.response();
        byte[] bodyBytes = httpResponse.body() == null ? new byte[0] : httpResponse.body().getBytes();
        long contentLength = parseContentLength(httpResponse.headerValue("Content-Length"));

        return new FetchResponse(
                httpResponse.statusCode(),
                bodyBytes,
                Utils.coalesce(httpResponse.headerValue("Content-Type")),
                contentLength
        );
    }

    private long parseContentLength(String rawContentLength)
    {
        if (Utils.isBlank(rawContentLength))
        {
            return -1L;
        }
        try
        {
            return Long.parseLong(rawContentLength.trim());
        }
        catch (NumberFormatException ignored)
        {
            return -1L;
        }
    }

    private boolean isCancellationError(Throwable ex)
    {
        if (ex == null)
        {
            return false;
        }
        return Utils.safeLower(Utils.coalesce(ex.getMessage())).contains("canceled by user");
    }

    private boolean isRetryableFetchError(IOException ex)
    {
        if (ex == null)
        {
            return false;
        }

        String message = Utils.safeLower(Utils.coalesce(ex.getMessage()));
        if (message.contains("canceled by user"))
        {
            return false;
        }

        return message.contains("timeout")
                || message.contains("connection")
                || message.contains("temporarily")
                || message.contains("reset")
                || message.contains("refused")
                || message.contains("http 5")
                || message.contains("http 429")
                || message.contains("no response");
    }

    private void sleepBackoff(int attempt)
    {
        try
        {
            long delay = (long) FETCH_RETRY_BACKOFF_MS * Math.max(1, attempt);
            Thread.sleep(delay);
        }
        catch (InterruptedException interrupted)
        {
            Thread.currentThread().interrupt();
        }
    }

    private String decodeResponseBody(HttpResponse response)
    {
        if (response == null)
        {
            return "";
        }

        byte[] bodyBytes = null;
        try
        {
            if (response.body() != null)
            {
                bodyBytes = response.body().getBytes();
            }
        }
        catch (Exception ignored)
        {
            bodyBytes = null;
        }

        String bodyToString = "";
        try
        {
            bodyToString = Utils.coalesce(response.bodyToString());
        }
        catch (Exception ignored)
        {
            bodyToString = "";
        }

        if (bodyBytes == null)
        {
            return bodyToString;
        }

        return decodeBytesBestEffort(bodyBytes, detectCharsetFromContentType(response), bodyToString);
    }

    private String readSpecFileContent(Path path) throws IOException
    {
        byte[] bytes = Files.readAllBytes(path);
        return decodeBytesBestEffort(bytes, "", "");
    }

    private boolean startsWith(byte[] bytes, int... prefix)
    {
        if (bytes == null || prefix == null || bytes.length < prefix.length)
        {
            return false;
        }
        for (int i = 0; i < prefix.length; i++)
        {
            if ((bytes[i] & 0xFF) != prefix[i])
            {
                return false;
            }
        }
        return true;
    }

    private String decodeBytesBestEffort(byte[] bodyBytes, String charsetFromHeader, String fallback)
    {
        if (bodyBytes == null || bodyBytes.length == 0)
        {
            return Utils.coalesce(fallback);
        }

        BomDecode bomDecode = detectBom(bodyBytes);
        if (bomDecode != null)
        {
            return decodeWithCharset(bodyBytes, bomDecode.charsetName(), bomDecode.offset());
        }

        List<String> candidates = new ArrayList<>();
        if (Utils.nonBlank(charsetFromHeader))
        {
            try
            {
                candidates.add(new String(bodyBytes, Charset.forName(charsetFromHeader)));
            }
            catch (Exception ignored)
            {
                // Ignore invalid charset declarations.
            }
        }

        String detectedCharset = detectCharsetFromBytes(bodyBytes);
        if (Utils.nonBlank(detectedCharset)
                && !detectedCharset.equalsIgnoreCase(charsetFromHeader))
        {
            try
            {
                candidates.add(new String(bodyBytes, Charset.forName(detectedCharset)));
            }
            catch (Exception ignored)
            {
                // Ignore invalid auto-detected charset.
            }
        }

        String utf8Strict = decodeUtf8Strict(bodyBytes);
        if (Utils.nonBlank(utf8Strict))
        {
            candidates.add(utf8Strict);
        }
        candidates.add(decodeUtf8Lenient(bodyBytes));
        candidates.add(new String(bodyBytes, Charset.forName("windows-1251")));
        if (Utils.nonBlank(fallback))
        {
            candidates.add(fallback);
        }

        return bestDecodedCandidate(candidates, fallback);
    }

    private String detectCharsetFromContentType(HttpResponse response)
    {
        try
        {
            return detectCharsetFromContentTypeValue(response.headerValue("Content-Type"));
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private String detectCharsetFromContentTypeValue(String contentType)
    {
        if (Utils.isBlank(contentType))
        {
            return "";
        }
        Matcher matcher = CHARSET_PATTERN.matcher(contentType);
        if (matcher.find())
        {
            return matcher.group(1);
        }
        return "";
    }

    private String detectCharsetFromBytes(byte[] bytes)
    {
        if (bytes == null || bytes.length == 0)
        {
            return "";
        }
        UniversalDetector detector = new UniversalDetector(null);
        detector.handleData(bytes, 0, Math.min(bytes.length, 64 * 1024));
        detector.dataEnd();
        String detected = Utils.coalesce(detector.getDetectedCharset());
        detector.reset();
        return detected;
    }

    private BomDecode detectBom(byte[] bytes)
    {
        if (startsWith(bytes, 0xEF, 0xBB, 0xBF))
        {
            return new BomDecode("UTF-8", 3);
        }
        if (startsWith(bytes, 0xFF, 0xFE))
        {
            return new BomDecode("UTF-16LE", 2);
        }
        if (startsWith(bytes, 0xFE, 0xFF))
        {
            return new BomDecode("UTF-16BE", 2);
        }
        return null;
    }

    private String decodeWithCharset(byte[] bytes, String charsetName, int offset)
    {
        if (bytes == null)
        {
            return "";
        }
        try
        {
            int safeOffset = Math.max(0, Math.min(offset, bytes.length));
            return new String(bytes, safeOffset, bytes.length - safeOffset, Charset.forName(charsetName));
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private String decodeUtf8Strict(byte[] bytes)
    {
        try
        {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes))
                    .toString();
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private String decodeUtf8Lenient(byte[] bytes)
    {
        try
        {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .decode(java.nio.ByteBuffer.wrap(bytes))
                    .toString();
        }
        catch (Exception ignored)
        {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private String bestDecodedCandidate(List<String> candidates, String fallback)
    {
        String best = Utils.coalesce(fallback);
        int bestScore = decodeScore(best);
        for (int i = 0; i < candidates.size(); i++)
        {
            String candidate = candidates.get(i);
            if (candidate == null)
            {
                continue;
            }
            int precedenceBonus = Math.max(0, candidates.size() - i);
            int score = decodeScore(candidate) + precedenceBonus;
            if (score > bestScore)
            {
                best = candidate;
                bestScore = score;
            }
        }
        return best;
    }

    private int decodeScore(String value)
    {
        if (Utils.isBlank(value))
        {
            return Integer.MIN_VALUE / 4;
        }

        int score = 0;
        String lower = Utils.safeLower(value);

        for (int i = 0; i < value.length(); i++)
        {
            char ch = value.charAt(i);
            if (ch >= '\u0400' && ch <= '\u04FF')
            {
                score += 4;
            }
            else if (Character.isLetterOrDigit(ch))
            {
                score += 1;
            }
            else if (ch == '\uFFFD')
            {
                score -= 8;
            }
        }

        if (lower.contains("openapi") || lower.contains("\"paths\"") || lower.contains("paths:"))
        {
            score += 25;
        }

        if (value.contains("Ð") || value.contains("Ñ") || value.contains("Ã"))
        {
            score -= 12;
        }
        if (CP1251_MOJIBAKE_PATTERN.matcher(value).find())
        {
            score -= 18;
        }

        return score;
    }

    private List<String> buildCandidateSpecUrls(String url)
    {
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        addCandidate(candidates, url);

        URI uri;
        try
        {
            uri = URI.create(url);
        }
        catch (Exception ex)
        {
            return List.copyOf(candidates);
        }

        for (String queryCandidate : extractCandidatesFromQuery(url, uri.getRawQuery()))
        {
            addCandidate(candidates, queryCandidate);
        }

        String origin = uriOrigin(uri);
        if (Utils.isBlank(origin))
        {
            return List.copyOf(candidates);
        }

        String path = Utils.coalesce(uri.getPath(), "/");
        String lowerPath = path.toLowerCase(Locale.ROOT);

        String directory = path;
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0)
        {
            directory = path.substring(0, lastSlash);
        }

        if (lowerPath.contains("swagger")
                || lowerPath.contains("api-docs")
                || lowerPath.endsWith("index.html"))
        {
            for (String endpoint : List.of("/v3/api-docs", "/v2/api-docs", "/swagger.json", "/openapi.json", "/openapi.yaml", "/api-docs"))
            {
                addCandidate(candidates, joinOriginPath(origin, endpoint));
                if (Utils.nonBlank(directory))
                {
                    addCandidate(candidates, joinOriginPath(origin, directory + endpoint));
                }
            }

            int swaggerIndex = lowerPath.indexOf("/swagger");
            if (swaggerIndex >= 0)
            {
                String beforeSwagger = path.substring(0, swaggerIndex);
                addCandidate(candidates, joinOriginPath(origin, beforeSwagger + "/v3/api-docs"));
                addCandidate(candidates, joinOriginPath(origin, beforeSwagger + "/v2/api-docs"));
                addCandidate(candidates, joinOriginPath(origin, beforeSwagger + "/openapi.json"));
                addCandidate(candidates, joinOriginPath(origin, beforeSwagger + "/swagger.json"));

                String swaggerRoot = path.substring(0, swaggerIndex + "/swagger".length());
                addCandidate(candidates, joinOriginPath(origin, swaggerRoot + "/v1/swagger.json"));
                addCandidate(candidates, joinOriginPath(origin, swaggerRoot + "/v2/swagger.json"));
            }
        }

        return List.copyOf(candidates);
    }

    private List<String> extractCandidatesFromQuery(String baseUrl, String rawQuery)
    {
        if (Utils.isBlank(rawQuery))
        {
            return List.of();
        }

        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        String[] pairs = rawQuery.split("[&;]");
        for (String pair : pairs)
        {
            if (Utils.isBlank(pair))
            {
                continue;
            }

            String[] keyValue = pair.split("=", 2);
            if (keyValue.length != 2)
            {
                continue;
            }

            String key = urlDecode(keyValue[0]).toLowerCase(Locale.ROOT);
            if (!"url".equals(key) && !"configurl".equals(key))
            {
                continue;
            }

            String value = urlDecode(keyValue[1]);
            String resolved = resolveAgainst(baseUrl, value);
            addCandidate(candidates, resolved);
        }
        return List.copyOf(candidates);
    }

    private List<String> extractReferencedUrls(String baseUrl, String payload)
    {
        if (Utils.isBlank(payload))
        {
            return List.of();
        }

        String probe = payload.length() > 350_000 ? payload.substring(0, 350_000) : payload;
        LinkedHashSet<String> discovered = new LinkedHashSet<>();
        Matcher matcher = URL_FIELD_PATTERN.matcher(probe);
        while (matcher.find())
        {
            String reference = matcher.group(1);
            String resolved = resolveAgainst(baseUrl, reference);
            addCandidate(discovered, resolved);
        }

        return List.copyOf(discovered);
    }

    private String resolveAgainst(String baseUrl, String candidate)
    {
        String normalized = normalizeToken(candidate);
        if (Utils.isBlank(normalized))
        {
            return "";
        }

        if (Utils.looksLikeHttpUrl(normalized))
        {
            return normalized;
        }

        try
        {
            URI base = URI.create(baseUrl);
            URI resolved = base.resolve(normalized);
            if (Utils.nonBlank(resolved.getScheme()) && Utils.nonBlank(resolved.getAuthority()))
            {
                return resolved.toString();
            }
        }
        catch (Exception ignored)
        {
            return "";
        }

        return "";
    }

    private String urlDecode(String value)
    {
        if (value == null)
        {
            return "";
        }
        try
        {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        }
        catch (Exception ignored)
        {
            return value;
        }
    }

    private String uriOrigin(URI uri)
    {
        if (uri == null || Utils.isBlank(uri.getScheme()) || Utils.isBlank(uri.getAuthority()))
        {
            return "";
        }
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    private String joinOriginPath(String origin, String path)
    {
        if (Utils.isBlank(origin) || Utils.isBlank(path))
        {
            return "";
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        return origin + normalized;
    }

    private boolean enqueueSpecCandidate(Deque<String> queue, Set<String> seen, String candidate, String allowedHost)
    {
        String normalized = normalizeToken(candidate);
        if (!Utils.looksLikeHttpUrl(normalized))
        {
            return false;
        }

        try
        {
            URI uri = URI.create(normalized);
            if (Utils.isBlank(uri.getScheme()) || Utils.isBlank(uri.getAuthority()))
            {
                return false;
            }
            // Never follow spec auto-discovery to a different host than the one the user entered.
            if (Utils.nonBlank(allowedHost) && !allowedHost.equalsIgnoreCase(uri.getHost()))
            {
                return false;
            }
        }
        catch (Exception ignored)
        {
            return false;
        }

        if (!seen.add(normalized))
        {
            return false;
        }

        queue.addLast(normalized);
        return true;
    }

    private String hostOf(String url)
    {
        try
        {
            return Utils.coalesce(URI.create(url).getHost());
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private void addCandidate(Set<String> candidates, String candidate)
    {
        if (candidates == null)
        {
            return;
        }

        String normalized = normalizeToken(candidate);
        if (!Utils.looksLikeHttpUrl(normalized))
        {
            return;
        }
        candidates.add(normalized);
    }

    private String conciseError(Exception ex)
    {
        String message = ex == null ? "" : Utils.coalesce(ex.getMessage());
        if (Utils.isBlank(message))
        {
            return ex == null ? "unknown error" : ex.getClass().getSimpleName();
        }

        String firstLine = message.lines().findFirst().orElse(message);
        String compact = firstLine.trim();
        return compact.length() > 180 ? compact.substring(0, 177) + "..." : compact;
    }

    private void applyUrlListLoadOutcome(UrlListLoadResult result)
    {
        replaceLoadFailures(result.failures());
        int totalCount = model.operations().size();
        int failed = result.failures().size();
        String canceledSuffix = result.canceled() ? ", canceled" : "";

        statusLabel.setText("URL list loaded (" + result.sourceLabel() + "): lines=" + result.totalLines()
                + ", accepted=" + result.acceptedUrls()
                + ", normalized=" + result.normalizedUrls()
                + ", specs=" + result.loadedSpecs() + "/" + result.acceptedUrls()
                + ", +" + result.addedOperations() + " operation(s), failed=" + failed
                + ", skipped=" + result.skippedLines() + canceledSuffix + ".");
        progressLabel.setText("Progress: " + result.processedUrls() + "/" + result.acceptedUrls()
                + (result.canceled() ? " (canceled)" : " (done)"));
        log("URL list load completed: source=" + result.sourceLabel()
                + ", lines=" + result.totalLines()
                + ", acceptedUrls=" + result.acceptedUrls()
                + ", normalizedUrls=" + result.normalizedUrls()
                + ", skippedLines=" + result.skippedLines()
                + ", specsLoaded=" + result.loadedSpecs()
                + ", processedUrls=" + result.processedUrls()
                + ", addedOperations=" + result.addedOperations()
                + ", failed=" + failed
                + ", canceled=" + result.canceled()
                + ", totalOperations=" + totalCount);

        if (!result.failures().isEmpty())
        {
            int maxPreview = Math.min(5, result.failures().size());
            for (int i = 0; i < maxPreview; i++)
            {
                log("URL list item failed: " + result.failures().get(i));
            }
            if (result.failures().size() > maxPreview)
            {
                log("URL list item failures omitted: +" + (result.failures().size() - maxPreview));
            }
        }
        if (result.loadedSpecs() == 0 && !"saved-session".equals(result.sourceLabel()))
        {
            showError("URL list load result", "No OpenAPI specs were loaded. Check Event Log for item-level errors.");
        }
        persistLoadedSources();
        persistUiState();
    }

    private void parseAndDisplaySpecAsync(
            String rawSpec,
            String sourceLabel,
            String sourceLocation,
            boolean preferLocationParsing,
            String statusMessage)
    {
        if (Utils.isBlank(rawSpec) && !preferLocationParsing)
        {
            showError("Parse error", "Specification content is empty.");
            return;
        }

        runBackgroundLoad(statusMessage, () -> parseSpec(rawSpec, sourceLabel, sourceLocation, preferLocationParsing), "Parse");
    }

    private ParseOutcome parseSpec(String rawSpec, String sourceLabel, String sourceLocation, boolean preferLocationParsing) throws Exception
    {
        log("Parsing spec from " + sourceLabel);

        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);
        options.setFlatten(false);
        // Remote spec loading is performed through Montoya. Do not let the Swagger parser
        // resolve HTTP(S) external $ref values via java.net.URLConnection.
        options.setSafelyResolveURL(true);
        options.setRemoteRefBlockList(List.of("*"));

        OpenAPIV3Parser parser = new OpenAPIV3Parser();
        SwaggerParseResult parseResult = null;

        // Parse content first to avoid a second network pull when URL content is already fetched.
        if (Utils.nonBlank(rawSpec))
        {
            parseResult = parser.readContents(rawSpec, new ArrayList<>(), options);
        }

        // Fallback to location parsing (supports relative external refs).
        if ((parseResult == null || parseResult.getOpenAPI() == null)
                && preferLocationParsing
                && Utils.nonBlank(sourceLocation)
                && !Utils.looksLikeHttpUrl(sourceLocation))
        {
            parseResult = parser.readLocation(sourceLocation, new ArrayList<>(), options);
        }

        if (parseResult == null || parseResult.getOpenAPI() == null)
        {
            String message = formatParseErrors(parseResult);
            throw new IllegalStateException(message);
        }

        return new ParseOutcome(parseResult.getOpenAPI(), parseResult, sourceLabel, sourceLocation);
    }

    private void runBackgroundLoad(String statusMessage, CheckedSupplier<ParseOutcome> task, String actionLabel)
    {
        if (disposed.get())
        {
            return;
        }

        if (loadingInProgress)
        {
            statusLabel.setText("OpenAPI loading is already in progress...");
            return;
        }

        loadingInProgress = true;
        cancelRequested = false;
        progressLabel.setText("Progress: running...");
        setLoadingState(true, statusMessage);

        CompletableFuture
                .supplyAsync(() -> {
                    try
                    {
                        return task.get();
                    }
                    catch (Exception ex)
                    {
                        throw new CompletionException(ex);
                    }
                }, workerPool)
                .whenComplete((outcome, throwable) -> SwingUtilities.invokeLater(() -> {
                    if (disposed.get())
                    {
                        return;
                    }
                    loadingInProgress = false;
                    cancelRequested = false;
                    setLoadingState(false, null);

                    if (throwable != null)
                    {
                        Throwable root = unwrap(throwable);
                        if (isCancellationError(root))
                        {
                            progressLabel.setText("Progress: canceled");
                            statusLabel.setText(actionLabel + " canceled.");
                            log(actionLabel + " canceled by user.");
                            return;
                        }
                        progressLabel.setText("Progress: failed");
                        registerLoadFailure(actionLabel, Utils.coalesce(root.getMessage(), root.getClass().getSimpleName()));
                        logError(actionLabel + " failed: " + root.getMessage(), toException(root));
                        showError(actionLabel + " error", "Unable to complete operation:\n" + root.getMessage());
                        return;
                    }

                    progressLabel.setText("Progress: done");
                    applyParseOutcome(outcome);
                }));
    }

    private int applyParseOutcome(ParseOutcome outcome)
    {
        int previousCount = model.operations().size();
        model.load(outcome.openAPI(), outcome.sourceLocation(), outcome.sourceLabel());
        refreshSourceSelector();
        refreshServerSelector();
        applyFilter();

        int totalCount = model.operations().size();
        int addedCount = Math.max(0, totalCount - previousCount);
        statusLabel.setText("Loaded from " + outcome.sourceLabel()
                + ": +" + addedCount + " operation(s), total " + totalCount + ".");

        if (outcome.parseResult().getMessages() != null && !outcome.parseResult().getMessages().isEmpty())
        {
            for (String warning : outcome.parseResult().getMessages())
            {
                log("Parser warning: " + warning);
            }
        }

        log("Loaded operations: +" + addedCount + ", total=" + totalCount);
        persistLoadedSources();
        persistUiState();
        return addedCount;
    }

    private int applyParseOutcomeOnEdt(ParseOutcome outcome) throws Exception
    {
        if (SwingUtilities.isEventDispatchThread())
        {
            return applyParseOutcome(outcome);
        }

        java.util.concurrent.atomic.AtomicInteger addedCount = new java.util.concurrent.atomic.AtomicInteger();
        AtomicReference<Exception> callError = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try
            {
                addedCount.set(applyParseOutcome(outcome));
            }
            catch (Exception ex)
            {
                callError.set(ex);
            }
        });
        if (callError.get() != null)
        {
            throw callError.get();
        }
        return addedCount.get();
    }

    private void setLoadingState(boolean loading, String statusText)
    {
        loadFileButton.setEnabled(!loading);
        loadUrlListButton.setEnabled(!loading);
        fetchButton.setEnabled(!loading);
        cancelLoadButton.setEnabled(loading);

        if (loading && Utils.nonBlank(statusText))
        {
            statusLabel.setText(statusText);
        }
    }

    private void requestCancelUrlListLoad()
    {
        if (!loadingInProgress)
        {
            return;
        }

        cancelRequested = true;
        progressLabel.setText("Progress: cancel requested...");
        statusLabel.setText("Cancellation requested. Waiting for current request to finish...");
    }

    private void publishUrlListProgress(int processed, int total, String current)
    {
        SwingUtilities.invokeLater(() -> {
            String suffix = Utils.nonBlank(current) ? " - " + current : "";
            progressLabel.setText("Progress: " + processed + "/" + total + suffix);
        });
    }

    private void registerLoadFailure(String source, String reason)
    {
        String normalizedSource = Utils.coalesce(source, "unknown");
        String normalizedReason = Utils.coalesce(reason, "unknown error");
        String line = normalizedSource + " -> " + normalizedReason;
        lastLoadFailures.add(line);
        refreshFailedRequestsArea();
    }

    private void replaceLoadFailures(List<String> failures)
    {
        lastLoadFailures.clear();
        if (failures != null)
        {
            failures.stream()
                    .filter(Utils::nonBlank)
                    .forEach(lastLoadFailures::add);
        }
        refreshFailedRequestsArea();
    }

    private void clearLoadErrors()
    {
        lastLoadFailures.clear();
        refreshFailedRequestsArea();
    }

    private void refreshFailedRequestsArea()
    {
        SwingUtilities.invokeLater(() -> {
            if (lastLoadFailures.isEmpty())
            {
                failedSummaryLabel.setText("Load errors: none.");
                copyFailedButton.setEnabled(false);
                clearFailedButton.setEnabled(false);
                return;
            }

            String first = compactErrorLine(lastLoadFailures.get(0));
            if (lastLoadFailures.size() == 1)
            {
                failedSummaryLabel.setText("Load errors: 1 (" + first + ")");
            }
            else
            {
                failedSummaryLabel.setText("Load errors: " + lastLoadFailures.size() + " (e.g. " + first + ")");
            }
            copyFailedButton.setEnabled(true);
            clearFailedButton.setEnabled(true);
        });
    }

    private String compactErrorLine(String line)
    {
        String compact = Utils.coalesce(line).replace('\n', ' ').trim();
        if (compact.length() > 120)
        {
            return compact.substring(0, 117) + "...";
        }
        return compact;
    }

    private void copyFailedUrlsToClipboard()
    {
        if (lastLoadFailures.isEmpty())
        {
            return;
        }
        Utils.copyToClipboard(String.join("\n", lastLoadFailures));
        statusLabel.setText("Copied failed URL list to clipboard.");
    }

    private void persistUiState()
    {
        try
        {
            PersistedObject store = extensionDataStore();
            if (store == null)
            {
                return;
            }

            store.setString(STATE_URL_FIELD, Utils.coalesce(urlField.getText()));
            store.setString(STATE_FILTER_FIELD, Utils.coalesce(filterField.getText()));
            store.setString(STATE_SERVER, Utils.coalesce(selectedServer(), DEFAULT_SERVER_ITEM));
            store.setString(STATE_SOURCE, Utils.coalesce(selectedSourceId()));
            store.setString(STATE_AUTH_TYPE, Utils.coalesce(selectedAuthSelection().id()));
            store.setString(STATE_AUTH_KEY, Utils.coalesce(authKeyField.getText()));
            // Never persist the auth secret (Bearer/OAuth2 token, Basic password, API key value): the
            // extension data store lives in the unencrypted Burp project file. Scrub anything an older
            // version may have written, and re-prompt the secret each session.
            store.deleteString(STATE_AUTH_VALUE);
            store.setString(STATE_SOURCES, String.join("\n", persistedSourceLocations()));
        }
        catch (Exception ex)
        {
            logError("Unable to persist UI state: " + ex.getMessage(), ex);
        }
    }

    private void restoreUiState()
    {
        try
        {
            PersistedObject store = extensionDataStore();
            if (store == null)
            {
                return;
            }

            String storedUrl = Utils.coalesce(store.getString(STATE_URL_FIELD));
            if (Utils.nonBlank(storedUrl))
            {
                urlField.setText(storedUrl);
            }

            String storedFilter = Utils.coalesce(store.getString(STATE_FILTER_FIELD));
            if (Utils.nonBlank(storedFilter))
            {
                filterField.setText(storedFilter);
            }

            String storedServer = Utils.coalesce(store.getString(STATE_SERVER), DEFAULT_SERVER_ITEM);
            restoredServer = Utils.coalesce(storedServer);

            String storedSource = Utils.coalesce(store.getString(STATE_SOURCE));
            restoredSourceId = Utils.coalesce(storedSource);

            String authType = Utils.coalesce(store.getString(STATE_AUTH_TYPE));
            selectAuthById(authType);
            authKeyField.setText(Utils.coalesce(store.getString(STATE_AUTH_KEY)));
            // The auth secret is intentionally never persisted, so it always starts empty per session.

            String sourcesRaw = Utils.coalesce(store.getString(STATE_SOURCES));
            if (Utils.nonBlank(sourcesRaw))
            {
                restoredSourceLocations = sourcesRaw.lines()
                        .map(String::trim)
                        .filter(Utils::nonBlank)
                        .distinct()
                        .toList();
            }
        }
        catch (Exception ex)
        {
            logError("Unable to restore UI state: " + ex.getMessage(), ex);
        }
    }

    private PersistedObject extensionDataStore()
    {
        try
        {
            return api.persistence() != null ? api.persistence().extensionData() : null;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    private List<String> persistedSourceLocations()
    {
        List<String> sources = new ArrayList<>();
        for (OpenApiSamplerModel.SourceContext sourceContext : model.availableSources())
        {
            if (sourceContext == null)
            {
                continue;
            }
            String location = Utils.coalesce(sourceContext.location(), sourceContext.id());
            if (Utils.nonBlank(location))
            {
                sources.add(location);
            }
        }
        return sources.stream().distinct().toList();
    }

    private void persistLoadedSources()
    {
        try
        {
            PersistedObject store = extensionDataStore();
            if (store == null)
            {
                return;
            }
            store.setString(STATE_SOURCES, String.join("\n", persistedSourceLocations()));
        }
        catch (Exception ex)
        {
            logError("Unable to persist loaded sources: " + ex.getMessage(), ex);
        }
    }

    private void restorePersistedSourcesAsync()
    {
        List<String> sourcesToRestore = restoredSourceLocations == null ? List.of() : List.copyOf(restoredSourceLocations);
        restoredSourceLocations = List.of();
        if (sourcesToRestore.isEmpty() || disposed.get() || loadingInProgress)
        {
            return;
        }

        loadingInProgress = true;
        cancelRequested = false;
        progressLabel.setText("Progress: restoring saved sources...");
        setLoadingState(true, "Restoring saved OpenAPI sources...");

        CompletableFuture
                .supplyAsync(() -> {
                    try
                    {
                        return fetchAndParseFromPersistedSources(sourcesToRestore);
                    }
                    catch (Exception ex)
                    {
                        throw new CompletionException(ex);
                    }
                }, workerPool)
                .whenComplete((result, throwable) -> SwingUtilities.invokeLater(() -> {
                    if (disposed.get())
                    {
                        return;
                    }
                    loadingInProgress = false;
                    cancelRequested = false;
                    setLoadingState(false, null);

                    if (throwable != null)
                    {
                        Throwable root = unwrap(throwable);
                        progressLabel.setText("Progress: failed");
                        logError("Saved source restore failed: " + root.getMessage(), toException(root));
                        return;
                    }

                    progressLabel.setText("Progress: done");
                    applyUrlListLoadOutcome(result);
                    statusLabel.setText("Session restored: loaded " + result.loadedSpecs()
                            + " source(s), failed " + result.failures().size() + ".");
                }));
    }

    private UrlListLoadResult fetchAndParseFromPersistedSources(List<String> sources) throws Exception
    {
        if (sources == null || sources.isEmpty())
        {
            return new UrlListLoadResult(List.of(), 0, 0, 0, 0, "saved-session", 0, 0, 0, false);
        }

        List<String> failures = new ArrayList<>();
        int processed = 0;
        int loadedSpecs = 0;
        int addedOperations = 0;
        boolean canceled = false;

        for (String source : sources)
        {
            if (cancelRequested || disposed.get())
            {
                canceled = true;
                break;
            }
            publishUrlListProgress(processed, sources.size(), "Restoring " + source);
            try
            {
                if (Utils.looksLikeHttpUrl(source))
                {
                    ParseOutcome outcome = fetchAndParseFromUrl(source);
                    addedOperations += applyParseOutcomeOnEdt(outcome);
                }
                else
                {
                    ParseOutcome outcome = parseFromLocalSource(source);
                    addedOperations += applyParseOutcomeOnEdt(outcome);
                }
                loadedSpecs++;
            }
            catch (Exception ex)
            {
                if (isCancellationError(ex))
                {
                    canceled = true;
                    break;
                }
                failures.add(source + " -> " + Utils.coalesce(ex.getMessage(), ex.getClass().getSimpleName()));
                registerLoadFailure(source, Utils.coalesce(ex.getMessage(), ex.getClass().getSimpleName()));
            }
            processed++;
            publishUrlListProgress(processed, sources.size(), "Restored " + source);
        }

        return new UrlListLoadResult(
                failures,
                sources.size(),
                sources.size(),
                0,
                0,
                "saved-session",
                processed,
                loadedSpecs,
                addedOperations,
                canceled
        );
    }

    private ParseOutcome parseFromLocalSource(String source) throws Exception
    {
        Path path;
        if (source.startsWith("file:"))
        {
            path = Path.of(URI.create(source));
        }
        else
        {
            path = Path.of(source);
        }
        String content = readSpecFileContent(path);
        String sourceLabel = path.getFileName() != null ? path.getFileName().toString() : path.toString();
        return parseSpec(content, sourceLabel, path.toUri().toString(), true);
    }

    private Throwable unwrap(Throwable throwable)
    {
        Throwable current = throwable;
        while (current instanceof CompletionException && current.getCause() != null)
        {
            current = current.getCause();
        }
        return current;
    }

    private Exception toException(Throwable throwable)
    {
        if (throwable instanceof Exception ex)
        {
            return ex;
        }
        return new Exception(throwable);
    }

    private String formatParseErrors(SwaggerParseResult parseResult)
    {
        if (parseResult == null || parseResult.getMessages() == null || parseResult.getMessages().isEmpty())
        {
            return "OpenAPI parser returned no model and no details.";
        }

        return String.join("\n", parseResult.getMessages());
    }

    private void refreshServerSelector()
    {
        String previous = (String) serverSelector.getSelectedItem();
        String targetServer = Utils.nonBlank(restoredServer) ? restoredServer : previous;
        String selectedSourceId = selectedSourceId();

        serverSelector.removeAllItems();
        serverSelector.addItem(DEFAULT_SERVER_ITEM);

        for (String server : model.availableServers(selectedSourceId))
        {
            serverSelector.addItem(server);
        }

        if (targetServer != null)
        {
            for (int i = 0; i < serverSelector.getItemCount(); i++)
            {
                if (targetServer.equals(serverSelector.getItemAt(i)))
                {
                    serverSelector.setSelectedIndex(i);
                    restoredServer = "";
                    return;
                }
            }
        }

        serverSelector.setSelectedIndex(0);
    }

    private void applyFilter()
    {
        List<OpenApiSamplerModel.OperationContext> filtered = model.filter(filterField.getText(), selectedServer(), selectedSourceId());
        table.setOperations(filtered);

        statusLabel.setText("Showing " + filtered.size() + " / " + model.operations().size() + " operation(s)");
        refreshRequestPreviewFromSelection();
    }

    private void scheduleFilterApply()
    {
        if (disposed.get())
        {
            return;
        }
        filterDebounceTimer.restart();
    }

    private void refreshSourceSelector()
    {
        String previous = selectedSourceId();
        String targetSourceId = Utils.nonBlank(restoredSourceId) ? restoredSourceId : previous;

        sourceSelector.removeAllItems();
        sourceSelector.addItem(SourceSelection.allSources());

        for (OpenApiSamplerModel.SourceContext source : model.availableSources())
        {
            if (source == null || Utils.isBlank(source.id()))
            {
                continue;
            }
            sourceSelector.addItem(new SourceSelection(source.id(), source.label()));
        }

        if (Utils.nonBlank(targetSourceId))
        {
            for (int i = 0; i < sourceSelector.getItemCount(); i++)
            {
                SourceSelection item = sourceSelector.getItemAt(i);
                if (item != null && targetSourceId.equals(item.id()))
                {
                    sourceSelector.setSelectedIndex(i);
                    restoredSourceId = "";
                    return;
                }
            }
        }
        sourceSelector.setSelectedIndex(0);
    }

    private String selectedSourceId()
    {
        Object selected = sourceSelector.getSelectedItem();
        if (selected instanceof SourceSelection sourceSelection)
        {
            return Utils.coalesce(sourceSelection.id());
        }
        return "";
    }

    private void onTableSelectionChanged(OpenApiSamplerModel.OperationContext operationContext)
    {
        if (operationContext == null)
        {
            setPreviewPlaceholder("Request preview: select an operation.");
            return;
        }

        updateRequestPreview(operationContext);
    }

    private void refreshRequestPreviewFromSelection()
    {
        OpenApiSamplerModel.OperationContext selectedOperation = table.firstSelectedOperation();
        if (selectedOperation == null)
        {
            setPreviewPlaceholder("Request preview: select an operation.");
            return;
        }
        updateRequestPreview(selectedOperation);
    }

    private void updateRequestPreview(OpenApiSamplerModel.OperationContext operationContext)
    {
        try
        {
            HttpRequest request = generateRequest(operationContext);
            requestPreviewEditor.setRequest(request);
            requestPreviewLabel.setText("Request preview: " + operationContext.method() + " " + operationContext.path());
            responsePreviewEditor.setResponse(requestGenerator.generateResponsePreview(operationContext));
            responsePreviewLabel.setText("Response preview: expected response from OpenAPI spec");
        }
        catch (Exception ex)
        {
            logError("Unable to build preview request for " + operationContext.method() + " " + operationContext.path() + ": " + ex.getMessage(), ex);
            setPreviewPlaceholder("Request preview: generation failed (" + ex.getClass().getSimpleName() + ")");
        }
    }

    private void setPreviewPlaceholder(String label)
    {
        requestPreviewLabel.setText(label);
        requestPreviewEditor.setRequest(previewPlaceholderRequest());
        responsePreviewLabel.setText("Response preview: select an operation.");
        responsePreviewEditor.setResponse(previewPlaceholderResponse());
    }

    private HttpRequest previewPlaceholderRequest()
    {
        return HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: preview.local\r\n\r\n");
    }

    private burp.api.montoya.http.message.responses.HttpResponse previewPlaceholderResponse()
    {
        return burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSelect an operation to preview the expected OpenAPI response."
        );
    }

    private void onRowAction(OpenApiSamplerTable.RowAction action, OpenApiSamplerModel.OperationContext operationContext)
    {
        try
        {
            HttpRequest request = generateRequest(operationContext);

            switch (action)
            {
                case COPY_AS_CURL -> copyAsCurl(request);
                case COPY_AS_PYTHON -> copyAsPython(request);
                default -> {
                }
            }
        }
        catch (Exception ex)
        {
            logError("Action failed for " + operationContext.method() + " " + operationContext.path() + ": " + ex.getMessage(), ex);
            showError("Action error", ex.getMessage());
        }
    }

    private void copyAsCurl(HttpRequest request)
    {
        String curl = Utils.toCurl(request);
        Utils.copyToClipboard(curl);
        log("Copied as curl");
        statusLabel.setText("curl command copied to clipboard.");
    }

    private void copyAsPython(HttpRequest request)
    {
        String python = Utils.toPythonRequests(request);
        Utils.copyToClipboard(python);
        log("Copied as Python requests");
        statusLabel.setText("Python requests snippet copied to clipboard.");
    }

    private void sendVisibleToRepeater()
    {
        List<OpenApiSamplerModel.OperationContext> operations = table.visibleOperations();
        if (operations.isEmpty())
        {
            showError("No operations", "There are no operations to generate.");
            return;
        }

        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Generating " + operations.size() + " request(s) for Repeater...");
        submitGenerationTask(() -> {
            int sent = 0;
            int failed = 0;
            for (OpenApiSamplerModel.OperationContext operation : operations)
            {
                try
                {
                    HttpRequest request = generateRequest(operation, context);
                    String tabName = repeaterTabName("All", operation, request);
                    api.repeater().sendToRepeater(request, tabName);
                    sent++;
                }
                catch (Exception ex)
                {
                    failed++;
                    logError("Failed to generate request for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                }
            }

            setStatusOnEdt("Generated " + sent + " request(s), failed: " + failed);
            log("Visible -> Repeater completed. Sent=" + sent + ", Failed=" + failed);
        });
    }

    private void onSelectionAction(OpenApiSamplerTable.SelectionAction action, List<OpenApiSamplerModel.OperationContext> selected)
    {
        if (action == null)
        {
            return;
        }

        switch (action)
        {
            case SEND_VISIBLE_TO_REPEATER -> sendVisibleToRepeater();
            case SEND_SELECTED_TO_REPEATER -> {
                if (!ensureSelectionForPopup(selected, "Send selected to Repeater"))
                {
                    return;
                }
                sendSelectedToRepeater(selected);
            }
            case SEND_SELECTED_TO_INTRUDER -> {
                if (!ensureSelectionForPopup(selected, "Send selected to Intruder"))
                {
                    return;
                }
                sendSelectedToIntruder(selected);
            }
            case SEND_SELECTED_TO_ACTIVE_SCAN -> {
                if (!ensureSelectionForPopup(selected, "Send selected to Active scan"))
                {
                    return;
                }
                sendSelectedToAudit(selected, true);
            }
            case SEND_SELECTED_TO_PASSIVE_SCAN -> {
                if (!ensureSelectionForPopup(selected, "Send selected to Passive scan"))
                {
                    return;
                }
                sendSelectedToAudit(selected, false);
            }
            case CHANGE_SELECTED_SERVER -> {
                if (!ensureSelectionForPopup(selected, "Change selected server"))
                {
                    return;
                }
                changeSelectedServer(selected);
            }
            case COPY_SELECTED_AS_CURL -> {
                if (!ensureSelectionForPopup(selected, "Copy selected as cURL"))
                {
                    return;
                }
                copySelectedAsCurl(selected);
            }
            case COPY_SELECTED_AS_PYTHON -> {
                if (!ensureSelectionForPopup(selected, "Copy selected as Python-Requests"))
                {
                    return;
                }
                copySelectedAsPython(selected);
            }
            case EXPORT_SELECTED_REQUESTS -> {
                if (!ensureSelectionForPopup(selected, "Export selected requests"))
                {
                    return;
                }
                exportSelectedRequests(selected);
            }
            case DELETE_SELECTED -> {
                if (!ensureSelectionForPopup(selected, "Delete selected rows"))
                {
                    return;
                }
                deleteSelectedOperations(selected, true);
            }
            case SELECT_ALL -> table.selectAllRows();
            case CLEAR_SELECTION -> table.clearSelection();
            default -> {
            }
        }
    }

    private boolean ensureSelectionForPopup(List<OpenApiSamplerModel.OperationContext> selected, String action)
    {
        if (selected == null || selected.isEmpty())
        {
            showError("No selection", "Select one or more rows first for: " + action);
            return false;
        }
        return true;
    }

    private void changeSelectedServer(List<OpenApiSamplerModel.OperationContext> selected)
    {
        String current = commonServer(selected);
        String server = promptForServerOverride(selected.size(), current);
        if (server == null)
        {
            return;
        }

        String normalizedServer = normalizeServerOverride(server);
        if (Utils.isBlank(normalizedServer))
        {
            showError("Invalid server", "Enter an HTTP or HTTPS server, for example http://127.0.0.1:18080.");
            return;
        }

        int updated = model.replaceServer(selected, normalizedServer);
        refreshSourceSelector();
        refreshServerSelector();
        serverSelector.setSelectedIndex(0);
        applyFilter();
        statusLabel.setText("Changed server for " + updated + " operation(s): " + normalizedServer);
        log("Changed selected operation server: updated=" + updated + ", server=" + normalizedServer);
    }

    private String promptForServerOverride(int selectedCount, String currentServer)
    {
        JComboBox<String> serverInput = new JComboBox<>();
        serverInput.setEditable(true);

        LinkedHashSet<String> choices = new LinkedHashSet<>();
        if (Utils.nonBlank(currentServer))
        {
            choices.add(currentServer);
        }
        choices.addAll(model.availableServers());
        for (String choice : choices)
        {
            serverInput.addItem(choice);
        }
        if (Utils.nonBlank(currentServer))
        {
            serverInput.setSelectedItem(currentServer);
        }

        int answer = JOptionPane.showConfirmDialog(
                dialogParent(),
                serverInput,
                "Change server for " + selectedCount + " selected operation(s)",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (answer != JOptionPane.OK_OPTION)
        {
            return null;
        }

        Object selected = serverInput.getEditor().getItem();
        return selected == null ? "" : String.valueOf(selected);
    }

    private String commonServer(List<OpenApiSamplerModel.OperationContext> selected)
    {
        if (selected == null || selected.isEmpty())
        {
            return "";
        }

        String first = firstServer(selected.get(0));
        if (Utils.isBlank(first))
        {
            return "";
        }
        for (OpenApiSamplerModel.OperationContext operation : selected)
        {
            if (!first.equals(firstServer(operation)))
            {
                return "";
            }
        }
        return first;
    }

    private String firstServer(OpenApiSamplerModel.OperationContext operation)
    {
        if (operation == null || operation.servers() == null || operation.servers().isEmpty())
        {
            return "";
        }
        return Utils.coalesce(operation.servers().get(0));
    }

    private String normalizeServerOverride(String rawServer)
    {
        String server = Utils.stripTrailingSlash(Utils.coalesce(rawServer));
        if (Utils.isBlank(server))
        {
            return "";
        }
        if (!Utils.looksLikeHttpUrl(server))
        {
            server = "http://" + server;
        }

        try
        {
            URI uri = URI.create(server);
            String scheme = Utils.safeLower(uri.getScheme());
            if (!("http".equals(scheme) || "https".equals(scheme)) || Utils.isBlank(uri.getAuthority()))
            {
                return "";
            }
            if (Utils.nonBlank(uri.getQuery()) || Utils.nonBlank(uri.getFragment()))
            {
                return "";
            }
            return Utils.stripTrailingSlash(uri.toString());
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private void deleteSelectedOperations(List<OpenApiSamplerModel.OperationContext> selected, boolean confirm)
    {
        if (confirm)
        {
            int answer = JOptionPane.showConfirmDialog(
                    dialogParent(),
                    "Delete " + selected.size() + " selected operation(s) from table?",
                    "Confirm delete",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );
            if (answer != JOptionPane.YES_OPTION)
            {
                return;
            }
        }

        int removed = model.removeOperations(selected);
        table.clearSelection();
        refreshSourceSelector();
        refreshServerSelector();
        applyFilter();
        persistLoadedSources();
        statusLabel.setText("Removed " + removed + " operation(s).");
        log("Removed selected operations: " + removed);
    }

    private void sendSelectedToRepeater(List<OpenApiSamplerModel.OperationContext> selected)
    {
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Selected -> Repeater: generating " + selected.size() + " request(s)...");
        submitGenerationTask(() -> {
            int sent = 0;
            int failed = 0;
            for (OpenApiSamplerModel.OperationContext operation : selected)
            {
                try
                {
                    HttpRequest request = generateRequest(operation, context);
                    String tabName = repeaterTabName("Selected", operation, request);
                    api.repeater().sendToRepeater(request, tabName);
                    sent++;
                }
                catch (Exception ex)
                {
                    failed++;
                    logError("Selected -> Repeater failed for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                }
            }

            setStatusOnEdt("Selected -> Repeater: sent=" + sent + ", failed=" + failed);
            log("Selected requests sent to Repeater. Sent=" + sent + ", Failed=" + failed);
        });
    }

    private String repeaterTabName(String bucket, OpenApiSamplerModel.OperationContext operation, HttpRequest request)
    {
        String host = "unknown-host";
        String endpoint = Utils.coalesce(operation != null ? operation.path() : null, "/");
        String method = Utils.coalesce(operation != null ? operation.method() : null, "GET").toUpperCase();

        try
        {
            String requestUrl = request != null ? request.url() : "";
            if (Utils.looksLikeHttpUrl(requestUrl))
            {
                URI uri = URI.create(requestUrl);
                if (Utils.nonBlank(uri.getHost()))
                {
                    host = uri.getHost();
                }
                else if (Utils.nonBlank(uri.getAuthority()))
                {
                    host = uri.getAuthority();
                }
            }
        }
        catch (Exception ignored)
        {
            // Keep fallback host when request URL cannot be parsed.
        }

        try
        {
            if (request != null && Utils.nonBlank(request.pathWithoutQuery()))
            {
                endpoint = request.pathWithoutQuery();
            }
        }
        catch (Exception ignored)
        {
            // Keep operation-path fallback.
        }

        return "OpenAPI Sampler / " + bucket + " / " + host + " / " + method + " " + endpoint;
    }

    private void sendSelectedToIntruder(List<OpenApiSamplerModel.OperationContext> selected)
    {
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Selected -> Intruder: generating " + selected.size() + " request(s)...");
        submitGenerationTask(() -> {
            int sent = 0;
            int failed = 0;
            for (OpenApiSamplerModel.OperationContext operation : selected)
            {
                try
                {
                    HttpRequest request = generateRequest(operation, context);
                    api.intruder().sendToIntruder(request);
                    sent++;
                }
                catch (Exception ex)
                {
                    failed++;
                    logError("Selected -> Intruder failed for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                }
            }

            setStatusOnEdt("Selected -> Intruder: sent=" + sent + ", failed=" + failed);
            log("Selected requests sent to Intruder. Sent=" + sent + ", Failed=" + failed);
        });
    }

    private void sendSelectedToAudit(List<OpenApiSamplerModel.OperationContext> selected, boolean active)
    {
        if (disposed.get())
        {
            return;
        }
        if (selected == null || selected.isEmpty())
        {
            return;
        }

        String mode = active ? "Active" : "Passive";
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText(mode + " scan: queuing " + selected.size() + " request(s)...");
        workerPool.submit(() -> queueSelectedForAudit(selected, active, context));
    }

    private void queueSelectedForAudit(
            List<OpenApiSamplerModel.OperationContext> selected,
            boolean active,
            GenerationContext context)
    {
        String mode = active ? "Active" : "Passive";
        Audit audit;
        try
        {
            // Always start a fresh, known-alive task for each send. The Montoya API gives no way to
            // detect that the user deleted a scan task in the dashboard (a deleted Audit handle keeps
            // answering statusMessage()/requestCount() and silently drops addRequest()), so reusing a
            // cached handle could route requests into a task that no longer exists, with no progress.
            audit = createAuditTask(active);
        }
        catch (Exception ex)
        {
            logError(mode + " scan unavailable: " + ex.getMessage(), ex);
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText(mode + " scan unavailable.");
                showError(
                        mode + " scan unavailable",
                        mode + " scan could not be started. Check Burp Scanner availability and license."
                );
            });
            return;
        }

        int queued = 0;
        int failed = 0;
        int recreated = 0;
        int retried = 0;
        for (OpenApiSamplerModel.OperationContext operation : selected)
        {
            HttpRequest request;
            try
            {
                request = generateRequest(operation, context);
            }
            catch (Exception ex)
            {
                failed++;
                logError(mode + " scan queue failed for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                continue;
            }

            try
            {
                audit.addRequest(request);
                queued++;
            }
            catch (Exception addEx)
            {
                if (!isAuditTaskUsable(audit))
                {
                    try
                    {
                        log(mode + " scan task is unavailable. Recreating task and retrying request.");
                        audit = createAuditTask(active);
                        recreated++;
                        audit.addRequest(request);
                        queued++;
                        retried++;
                    }
                    catch (Exception retryEx)
                    {
                        failed++;
                        logError(mode + " scan retry failed for " + operation.method() + " " + operation.path() + ": " + retryEx.getMessage(), retryEx);
                    }
                }
                else
                {
                    failed++;
                    logError(mode + " scan queue failed for " + operation.method() + " " + operation.path() + ": " + addEx.getMessage(), addEx);
                }
            }
        }

        int queuedFinal = queued;
        int failedFinal = failed;
        int recreatedFinal = recreated;
        int retriedFinal = retried;
        SwingUtilities.invokeLater(() ->
                statusLabel.setText(mode + " scan queued: queued=" + queuedFinal
                        + ", failed=" + failedFinal
                        + ", recreated=" + recreatedFinal
                        + ", retried=" + retriedFinal + "."));
        log(mode + " scan queued for selected operations. Queued=" + queuedFinal
                + ", Failed=" + failedFinal
                + ", Recreated=" + recreatedFinal
                + ", Retried=" + retriedFinal);
    }

    private boolean isAuditTaskUsable(Audit task)
    {
        if (task == null)
        {
            return false;
        }
        try
        {
            task.statusMessage();
            task.requestCount();
            return true;
        }
        catch (Exception ignored)
        {
            return false;
        }
    }

    private Audit createAuditTask(boolean active)
    {
        BuiltInAuditConfiguration configuration = active
                ? BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                : BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS;
        Audit created = api.scanner().startAudit(AuditConfiguration.auditConfiguration(configuration));
        log((active ? "Active" : "Passive") + " audit task started.");
        return created;
    }

    private void copySelectedAsCurl(List<OpenApiSamplerModel.OperationContext> selected)
    {
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Generating cURL for " + selected.size() + " selected operation(s)...");
        submitGenerationTask(() -> {
            StringBuilder all = new StringBuilder();
            int copied = 0;
            int failed = 0;

            for (OpenApiSamplerModel.OperationContext operation : selected)
            {
                try
                {
                    HttpRequest request = generateRequest(operation, context);
                    if (all.length() > 0)
                    {
                        all.append("\n\n# ----------------------------------------\n\n");
                    }
                    all.append("# ").append(operation.method()).append(' ').append(operation.path()).append('\n');
                    all.append(Utils.toCurl(request));
                    copied++;
                }
                catch (Exception ex)
                {
                    failed++;
                    logError("Copy cURL failed for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                }
            }

            finishClipboardCopy(all.toString(), copied, failed, "cURL");
        });
    }

    private void copySelectedAsPython(List<OpenApiSamplerModel.OperationContext> selected)
    {
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Generating Python requests for " + selected.size() + " selected operation(s)...");
        submitGenerationTask(() -> {
            StringBuilder all = new StringBuilder();
            int copied = 0;
            int failed = 0;

            for (OpenApiSamplerModel.OperationContext operation : selected)
            {
                try
                {
                    HttpRequest request = generateRequest(operation, context);
                    if (all.length() > 0)
                    {
                        all.append("\n\n# ========================================\n\n");
                    }
                    all.append("# ").append(operation.method()).append(' ').append(operation.path()).append('\n');
                    all.append(Utils.toPythonRequests(request));
                    copied++;
                }
                catch (Exception ex)
                {
                    failed++;
                    logError("Copy Python failed for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                }
            }

            finishClipboardCopy(all.toString(), copied, failed, "Python");
        });
    }

    private void finishClipboardCopy(String content, int copied, int failed, String label)
    {
        if (copied <= 0)
        {
            setStatusOnEdt("Copied " + label + " for 0 selected operation(s), failed: " + failed);
            return;
        }
        SwingUtilities.invokeLater(() -> {
            Utils.copyToClipboard(content);
            statusLabel.setText("Copied " + label + " for " + copied + " selected operation(s), failed: " + failed);
        });
        log("Copied selected as " + label + ". Copied=" + copied + ", Failed=" + failed);
    }

    private void exportSelectedRequests(List<OpenApiSamplerModel.OperationContext> selected)
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export selected requests");
        chooser.setSelectedFile(new File("openapi-sampler-requests.txt"));

        int result = chooser.showSaveDialog(rootPanel);
        if (result != JFileChooser.APPROVE_OPTION)
        {
            return;
        }

        Path outputPath = chooser.getSelectedFile().toPath();
        GenerationContext context = generationContextSnapshot();
        statusLabel.setText("Exporting " + selected.size() + " request(s)...");
        submitGenerationTask(() -> {
            ExportDocument exportDocument;
            try
            {
                exportDocument = buildExportDocument(selected, context);
                if (Utils.isBlank(exportDocument.content()))
                {
                    setStatusOnEdt("Export produced no requests.");
                    showError("Export error", "No requests were exported.");
                    return;
                }
                Files.writeString(
                        outputPath,
                        exportDocument.content(),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE
                );
            }
            catch (Exception ex)
            {
                logError("Export failed: " + ex.getMessage(), ex);
                setStatusOnEdt("Export failed.");
                showError("Export error", ex.getMessage());
                return;
            }

            int exported = exportDocument.exported();
            int failed = exportDocument.failed();
            setStatusOnEdt("Exported " + exported + " request(s), failed: " + failed + " -> " + outputPath);
            log("Exported selected requests. Exported=" + exported + ", Failed=" + failed + ", File=" + outputPath);
        });
    }

    private ExportDocument buildExportDocument(List<OpenApiSamplerModel.OperationContext> selected)
    {
        return buildExportDocument(selected, generationContextSnapshot());
    }

    private ExportDocument buildExportDocument(List<OpenApiSamplerModel.OperationContext> selected, GenerationContext context)
    {
        if (selected == null || selected.isEmpty())
        {
            return new ExportDocument("", 0, 0);
        }

        StringBuilder all = new StringBuilder();
        int exported = 0;
        int failed = 0;
        for (OpenApiSamplerModel.OperationContext operation : selected)
        {
            HttpRequest request;
            try
            {
                request = generateRequest(operation, context);
            }
            catch (Exception ex)
            {
                logError("Export skipped for " + operation.method() + " " + operation.path() + ": " + ex.getMessage(), ex);
                failed++;
                continue;
            }

            if (exported > 0)
            {
                all.append("\n\n============================================================\n\n");
            }

            String server = request.url();
            try
            {
                URI uri = URI.create(request.url());
                if (Utils.nonBlank(uri.getScheme()) && Utils.nonBlank(uri.getAuthority()))
                {
                    server = uri.getScheme() + "://" + uri.getAuthority();
                }
            }
            catch (Exception ignored)
            {
                // Keep full URL fallback.
            }

            all.append("Source: ").append(Utils.coalesce(operation.sourceLabel(), operation.sourceId())).append('\n');
            all.append("Method: ").append(operation.method()).append('\n');
            all.append("Path: ").append(operation.path()).append('\n');
            all.append("Server: ").append(server).append('\n');
            all.append('\n');
            all.append("[RAW HTTP]\n");
            all.append(request).append('\n');
            all.append('\n');
            all.append("[CURL]\n");
            all.append(Utils.toCurl(request)).append('\n');
            all.append('\n');
            all.append("[PYTHON REQUESTS]\n");
            all.append(Utils.toPythonRequests(request)).append('\n');

            exported++;
        }
        return new ExportDocument(all.toString(), exported, failed);
    }

    private String selectedServer()
    {
        Object selected = serverSelector.getSelectedItem();
        return selected == null ? DEFAULT_SERVER_ITEM : String.valueOf(selected);
    }

    private AuthSelection selectedAuthSelection()
    {
        Object selected = authSelector.getSelectedItem();
        if (selected instanceof AuthSelection authSelection)
        {
            return authSelection;
        }
        return AuthSelection.none();
    }

    private RequestGenerator.AuthProfile selectedAuthProfile()
    {
        AuthSelection selection = selectedAuthSelection();
        String key = Utils.coalesce(authKeyField.getText());
        String value = Utils.coalesce(authValueField.getText());
        if (selection.authType() == RequestGenerator.AuthType.NONE)
        {
            key = "";
            value = "";
        }
        else if (selection.authType() == RequestGenerator.AuthType.BEARER
                || selection.authType() == RequestGenerator.AuthType.OAUTH2_BEARER)
        {
            key = "";
        }
        return new RequestGenerator.AuthProfile(
                selection.authType(),
                key,
                value
        );
    }

    private void selectAuthById(String id)
    {
        String target = Utils.coalesce(id);
        if (Utils.isBlank(target))
        {
            authSelector.setSelectedIndex(0);
            return;
        }
        for (int i = 0; i < authSelector.getItemCount(); i++)
        {
            AuthSelection authSelection = authSelector.getItemAt(i);
            if (authSelection != null && target.equals(authSelection.id()))
            {
                authSelector.setSelectedIndex(i);
                return;
            }
        }
        authSelector.setSelectedIndex(0);
    }

    private void updateAuthFieldHints()
    {
        AuthSelection selection = selectedAuthSelection();
        if (selection.authType() == RequestGenerator.AuthType.NONE)
        {
            setAuthFieldState(false, "Key:", "Authentication key", false, "Value:", "Authentication value");
            return;
        }
        if (selection.authType() == RequestGenerator.AuthType.BASIC)
        {
            setAuthFieldState(
                    true,
                    "Username:",
                    "Basic auth username.",
                    true,
                    "Password:",
                    "Basic auth password."
            );
            return;
        }
        if (selection.authType() == RequestGenerator.AuthType.API_KEY_HEADER)
        {
            setAuthFieldState(
                    true,
                    "Header name:",
                    "Header name to add, for example X-Api-Key.",
                    true,
                    "Value:",
                    "API key value."
            );
            return;
        }
        if (selection.authType() == RequestGenerator.AuthType.API_KEY_QUERY)
        {
            setAuthFieldState(
                    true,
                    "Query name:",
                    "Query parameter name to add, for example api_key.",
                    true,
                    "Value:",
                    "API key value."
            );
            return;
        }
        if (selection.authType() == RequestGenerator.AuthType.BEARER
                || selection.authType() == RequestGenerator.AuthType.OAUTH2_BEARER)
        {
            setAuthFieldState(
                    false,
                    "Key:",
                    "Not used for bearer tokens.",
                    true,
                    "Token:",
                    "Bearer token. The generated request uses Authorization: Bearer <token>."
            );
            return;
        }
        setAuthFieldState(true, "Key:", "Authentication key", true, "Value:", "Authentication value");
    }

    private void setAuthFieldState(
            boolean keyVisible,
            String keyLabel,
            String keyTooltip,
            boolean valueVisible,
            String valueLabel,
            String valueTooltip)
    {
        authKeyLabel.setText(keyLabel);
        authKeyLabel.setVisible(keyVisible);
        authKeyField.setVisible(keyVisible);
        authKeyField.setEnabled(keyVisible);
        authKeyField.setToolTipText(keyTooltip);

        authValueLabel.setText(valueLabel);
        authValueLabel.setVisible(valueVisible);
        authValueField.setVisible(valueVisible);
        authValueField.setEnabled(valueVisible);
        authValueField.setToolTipText(valueTooltip);

        rootPanel.revalidate();
        rootPanel.repaint();
    }

    private RequestGenerator.GenerationOptions generationOptionsSnapshot()
    {
        return new RequestGenerator.GenerationOptions(selectedAuthProfile());
    }

    /**
     * Immutable snapshot of the UI-derived inputs needed to generate requests. Captured on the EDT so
     * that request generation (which can be heavy for large/complex specs) runs on a worker thread
     * without touching or blocking Swing.
     */
    private record GenerationContext(String server, String sourceId, RequestGenerator.GenerationOptions options)
    {
    }

    private GenerationContext generationContextSnapshot()
    {
        return new GenerationContext(selectedServer(), selectedSourceId(), generationOptionsSnapshot());
    }

    private HttpRequest generateRequest(OpenApiSamplerModel.OperationContext operationContext)
    {
        return generateRequest(operationContext, generationContextSnapshot());
    }

    private HttpRequest generateRequest(
            OpenApiSamplerModel.OperationContext operationContext,
            GenerationContext context)
    {
        return requestGenerator.generate(
                operationContext,
                context.server(),
                fallbackServersForOperation(operationContext, context.sourceId()),
                context.options()
        );
    }

    private List<String> fallbackServersForOperation(
            OpenApiSamplerModel.OperationContext operationContext,
            String selectedSourceIdSnapshot)
    {
        if (operationContext != null && Utils.nonBlank(operationContext.sourceId()))
        {
            List<String> bySource = model.availableServers(operationContext.sourceId());
            if (bySource != null && !bySource.isEmpty())
            {
                return bySource;
            }
        }
        return model.availableServers(selectedSourceIdSnapshot);
    }

    private String extractRequestUrl(HttpRequestResponse requestResponse)
    {
        try
        {
            return requestResponse != null && requestResponse.request() != null
                    ? requestResponse.request().url()
                    : "";
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private String extractResponseBody(HttpRequestResponse requestResponse)
    {
        try
        {
            return requestResponse != null && requestResponse.response() != null
                    ? decodeResponseBody(requestResponse.response())
                    : "";
        }
        catch (Exception ignored)
        {
            return "";
        }
    }

    private void showError(String title, String message)
    {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(dialogParent(), message, title, JOptionPane.ERROR_MESSAGE));
    }

    private void setStatusOnEdt(String text)
    {
        SwingUtilities.invokeLater(() -> statusLabel.setText(text));
    }

    /**
     * Runs request generation (and the follow-up Repeater/Intruder/clipboard/export work) on the worker
     * pool so the Swing EDT is never blocked while sampling a potentially large selection.
     */
    private void submitGenerationTask(Runnable backgroundWork)
    {
        if (disposed.get())
        {
            return;
        }
        workerPool.submit(() -> {
            try
            {
                backgroundWork.run();
            }
            catch (Exception ex)
            {
                logError("Background generation task failed: " + ex.getMessage(), ex);
            }
        });
    }

    private Component dialogParent()
    {
        try
        {
            Component suiteFrame = api.userInterface().swingUtils().suiteFrame();
            return suiteFrame != null ? suiteFrame : rootPanel;
        }
        catch (Exception ignored)
        {
            return rootPanel;
        }
    }

    private void log(String message)
    {
        api.logging().logToOutput(EXTENSION_PREFIX + message);
        api.logging().raiseInfoEvent(EXTENSION_PREFIX + message);
    }

    private void logError(String message, Exception ex)
    {
        api.logging().logToError(EXTENSION_PREFIX + message);
        api.logging().raiseErrorEvent(EXTENSION_PREFIX + message);
        if (ex != null)
        {
            api.logging().logToError(EXTENSION_PREFIX + "Exception type: " + ex.getClass().getSimpleName());
        }
    }

    private record HttpFetchResult(
            String url,
            short statusCode,
            String body)
    {
    }

    static final class FetchResponse
    {
        private final short statusCode;
        private final byte[] bodyBytes;
        private final String contentType;
        private final long contentLength;

        FetchResponse(short statusCode, byte[] bodyBytes, String contentType, long contentLength)
        {
            this.statusCode = statusCode;
            this.bodyBytes = bodyBytes == null ? new byte[0] : bodyBytes.clone();
            this.contentType = Utils.coalesce(contentType);
            this.contentLength = contentLength;
        }

        short statusCode()
        {
            return statusCode;
        }

        byte[] bodyBytes()
        {
            return bodyBytes.clone();
        }

        String contentType()
        {
            return contentType;
        }

        long contentLength()
        {
            return contentLength;
        }
    }

    private record BomDecode(String charsetName, int offset)
    {
    }

    private record ExportDocument(String content, int exported, int failed)
    {
    }

    @FunctionalInterface
    interface SpecFetcher
    {
        FetchResponse fetch(String url, long responseTimeoutMs, long perAttemptDeadlineMs, boolean followRedirects) throws Exception;
    }

    private record ParseOutcome(OpenAPI openAPI, SwaggerParseResult parseResult, String sourceLabel, String sourceLocation)
    {
    }

    private record UrlListLoadResult(
            List<String> failures,
            int totalLines,
            int acceptedUrls,
            int normalizedUrls,
            int skippedLines,
            String sourceLabel,
            int processedUrls,
            int loadedSpecs,
            int addedOperations,
            boolean canceled)
    {
    }

    private record UrlListParseResult(
            List<String> urls,
            List<String> normalizationNotes,
            List<String> skipNotes,
            int totalLines,
            int normalizedCount)
    {
    }

    private record UrlLineDecision(
            boolean accepted,
            String url,
            boolean normalized,
            String note)
    {
        private static UrlLineDecision skipped(String note)
        {
            return new UrlLineDecision(false, "", false, note);
        }

        private static UrlLineDecision accepted(String url, boolean normalized, String note)
        {
            return new UrlLineDecision(true, url, normalized, note);
        }
    }

    private record SourceSelection(String id, String label)
    {
        private static SourceSelection allSources()
        {
            return new SourceSelection("", DEFAULT_SOURCE_ITEM);
        }

        @Override
        public String toString()
        {
            return Utils.coalesce(label, DEFAULT_SOURCE_ITEM);
        }
    }

    private record AuthSelection(String id, String label, RequestGenerator.AuthType authType)
    {
        private static AuthSelection none()
        {
            return new AuthSelection("none", "None", RequestGenerator.AuthType.NONE);
        }

        private static AuthSelection bearer()
        {
            return new AuthSelection("bearer", "Bearer", RequestGenerator.AuthType.BEARER);
        }

        private static AuthSelection basic()
        {
            return new AuthSelection("basic", "Basic", RequestGenerator.AuthType.BASIC);
        }

        private static AuthSelection apiKeyHeader()
        {
            return new AuthSelection("api_key_header", "API Key (Header)", RequestGenerator.AuthType.API_KEY_HEADER);
        }

        private static AuthSelection apiKeyQuery()
        {
            return new AuthSelection("api_key_query", "API Key (Query)", RequestGenerator.AuthType.API_KEY_QUERY);
        }

        private static AuthSelection oauth2Bearer()
        {
            return new AuthSelection("oauth2_bearer", "OAuth2 Bearer", RequestGenerator.AuthType.OAUTH2_BEARER);
        }

        @Override
        public String toString()
        {
            return Utils.coalesce(label, "None");
        }
    }

    @FunctionalInterface
    private interface CheckedSupplier<T>
    {
        T get() throws Exception;
    }
}
