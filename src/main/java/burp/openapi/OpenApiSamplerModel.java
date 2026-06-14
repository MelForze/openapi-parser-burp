package burp.openapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.PathItem.HttpMethod;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.servers.ServerVariable;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Domain model for currently loaded OpenAPI definition and flattened operations table.
 */
public final class OpenApiSamplerModel
{
    private OpenAPI openAPI;
    private String sourceLocation;
    private final List<OperationContext> operations = new ArrayList<>();
    private final List<String> availableServers = new ArrayList<>();
    private final LinkedHashMap<String, SourceContext> sources = new LinkedHashMap<>();
    private final LinkedHashMap<String, LinkedHashSet<String>> serversBySource = new LinkedHashMap<>();

    public synchronized OpenAPI openAPI()
    {
        return openAPI;
    }

    public synchronized String sourceLocation()
    {
        return sourceLocation;
    }

    public synchronized List<OperationContext> operations()
    {
        // Return an immutable snapshot (not a live view): callers on worker threads must be able to
        // iterate the result safely even while the EDT mutates the model via load()/replaceServer().
        return List.copyOf(operations);
    }

    public synchronized List<String> availableServers()
    {
        return List.copyOf(availableServers);
    }

    public synchronized List<String> availableServers(String selectedSourceId)
    {
        if (Utils.isBlank(selectedSourceId))
        {
            return availableServers();
        }

        LinkedHashSet<String> scoped = serversBySource.get(selectedSourceId);
        if (scoped == null || scoped.isEmpty())
        {
            return List.of();
        }
        return List.copyOf(scoped);
    }

    public synchronized List<SourceContext> availableSources()
    {
        return List.copyOf(sources.values());
    }

    public synchronized int removeOperations(Collection<OperationContext> toRemove)
    {
        if (toRemove == null || toRemove.isEmpty())
        {
            return 0;
        }

        int before = operations.size();
        operations.removeIf(toRemove::contains);
        recalculateIndexes();
        return before - operations.size();
    }

    public synchronized int replaceServer(Collection<OperationContext> selectedOperations, String server)
    {
        String normalizedServer = Utils.stripTrailingSlash(Utils.coalesce(server));
        if (selectedOperations == null || selectedOperations.isEmpty() || Utils.isBlank(normalizedServer))
        {
            return 0;
        }

        Set<OperationContext> targets = new LinkedHashSet<>(selectedOperations);
        int updated = 0;
        for (int i = 0; i < operations.size(); i++)
        {
            OperationContext operation = operations.get(i);
            if (operation == null || !targets.contains(operation))
            {
                continue;
            }

            operations.set(i, operation.withServer(normalizedServer));
            updated++;
        }

        if (updated > 0)
        {
            recalculateIndexes();
        }
        return updated;
    }

    public synchronized void clear()
    {
        openAPI = null;
        sourceLocation = null;
        operations.clear();
        availableServers.clear();
        sources.clear();
        serversBySource.clear();
    }

    public synchronized void load(OpenAPI parsedOpenApi, String source)
    {
        load(parsedOpenApi, source, source);
    }

    public synchronized void load(OpenAPI parsedOpenApi, String source, String sourceLabel)
    {
        Objects.requireNonNull(parsedOpenApi, "parsedOpenApi must not be null");

        this.openAPI = parsedOpenApi;
        this.sourceLocation = source;
        String normalizedSourceLabel = Utils.coalesce(sourceLabel, source, "unknown source");
        String sourceId = sourceId(source, normalizedSourceLabel);
        SourceContext sourceContext = new SourceContext(sourceId, normalizedSourceLabel, source);
        sources.putIfAbsent(sourceId, sourceContext);
        serversBySource.computeIfAbsent(sourceId, ignored -> new LinkedHashSet<>());

        final Set<String> existingOperationKeys = new LinkedHashSet<>();
        for (OperationContext existing : operations)
        {
            if (existing == null)
            {
                continue;
            }
            if (sourceId.equals(existing.sourceId()))
            {
                existingOperationKeys.add(operationKey(existing));
            }
        }

        final String sourceDefaultServer = defaultServerFromSource(source);
        final LinkedHashSet<String> globalServers = collectResolvedServers(parsedOpenApi.getServers(), source);
        if (globalServers.isEmpty())
        {
            globalServers.add(sourceDefaultServer);
        }
        LinkedHashSet<String> sourceServers = serversBySource.computeIfAbsent(sourceId, ignored -> new LinkedHashSet<>());
        for (String server : globalServers)
        {
            if (Utils.nonBlank(server))
            {
                sourceServers.add(server);
            }
        }
        recalculateAvailableServers();

        if (parsedOpenApi.getPaths() == null || parsedOpenApi.getPaths().isEmpty())
        {
            return;
        }

        for (Map.Entry<String, PathItem> pathEntry : parsedOpenApi.getPaths().entrySet())
        {
            final String path = pathEntry.getKey();
            final PathItem pathItem = pathEntry.getValue();
            if (pathItem == null)
            {
                continue;
            }

            final Map<HttpMethod, Operation> operationMap = pathItem.readOperationsMap();
            if (operationMap == null || operationMap.isEmpty())
            {
                continue;
            }

            for (Map.Entry<HttpMethod, Operation> operationEntry : operationMap.entrySet())
            {
                final HttpMethod httpMethod = operationEntry.getKey();
                final Operation operation = operationEntry.getValue();
                if (httpMethod == null || operation == null)
                {
                    continue;
                }

                final List<Parameter> mergedParameters = mergeParameters(pathItem, operation);
                final LinkedHashSet<String> operationServers = resolveServersForOperation(pathItem, operation, globalServers, source);

                if (operationServers.isEmpty())
                {
                    operationServers.addAll(globalServers);
                }
                if (operationServers.isEmpty())
                {
                    operationServers.add(sourceDefaultServer);
                }

                final String summary = Utils.repairMojibake(
                        Utils.coalesce(operation.getSummary(), operation.getDescription(), operation.getOperationId(), "-")
                );
                final String operationId = Utils.repairMojibake(Utils.coalesce(operation.getOperationId(), "-"));
                final List<String> tags = operation.getTags() == null ? List.of() : List.copyOf(operation.getTags());

                List<String> rowServers = operationServers.stream().filter(Utils::nonBlank).toList();
                if (rowServers.isEmpty())
                {
                    rowServers = List.of(sourceDefaultServer);
                }

                for (String rowServer : rowServers)
                {
                    OperationContext operationContext = new OperationContext(
                            sourceId,
                            normalizedSourceLabel,
                            source,
                            httpMethod.name().toUpperCase(),
                            path,
                            summary,
                            operationId,
                            tags,
                            List.of(rowServer),
                            mergedParameters,
                            operation.getRequestBody(),
                            operation
                    );

                    String key = operationKey(operationContext);
                    if (!existingOperationKeys.add(key))
                    {
                        continue;
                    }

                    operations.add(operationContext);
                }
            }
        }

        operations.sort((a, b) -> {
            int byPath = a.path().compareToIgnoreCase(b.path());
            if (byPath != 0)
            {
                return byPath;
            }
            int byMethod = a.method().compareToIgnoreCase(b.method());
            if (byMethod != 0)
            {
                return byMethod;
            }
            return a.serversAsString().compareToIgnoreCase(b.serversAsString());
        });

        recalculateIndexes();
    }

    private String operationKey(OperationContext operationContext)
    {
        if (operationContext == null)
        {
            return "";
        }

        return operationContext.method() + "|"
                + operationContext.path() + "|"
                + operationContext.operationId() + "|"
                + operationContext.summary() + "|"
                + operationContext.serversAsString();
    }

    public synchronized List<OperationContext> filter(String query)
    {
        return filter(query, null, null);
    }

    public synchronized List<OperationContext> filter(String query, String selectedServer)
    {
        return filter(query, selectedServer, null);
    }

    public synchronized List<OperationContext> filter(String query, String selectedServer, String selectedSourceId)
    {
        final String normalized = Utils.safeLower(query).trim();
        final boolean filterByServer = Utils.nonBlank(selectedServer) && !"(Operation default)".equals(selectedServer);
        final boolean filterBySource = Utils.nonBlank(selectedSourceId);

        if (normalized.isEmpty() && !filterByServer && !filterBySource)
        {
            return List.copyOf(operations);
        }

        final List<OperationContext> filtered = new ArrayList<>();
        for (OperationContext operation : operations)
        {
            if (filterBySource && !selectedSourceId.equals(operation.sourceId()))
            {
                continue;
            }
            if (filterByServer && !operation.servers().contains(selectedServer))
            {
                continue;
            }
            if (normalized.isEmpty() || matches(operation, normalized))
            {
                filtered.add(operation);
            }
        }
        return filtered;
    }

    private boolean matches(OperationContext operation, String query)
    {
        if (query == null || query.isEmpty())
        {
            return true;
        }

        if (operation.method().toLowerCase().contains(query))
        {
            return true;
        }
        if (operation.path().toLowerCase().contains(query))
        {
            return true;
        }
        if (operation.summary().toLowerCase().contains(query))
        {
            return true;
        }
        if (operation.operationId().toLowerCase().contains(query))
        {
            return true;
        }
        if (Utils.joinTags(operation.tags()).toLowerCase().contains(query))
        {
            return true;
        }
        if (operation.parametersSummary().toLowerCase().contains(query))
        {
            return true;
        }
        if (operation.requestBodySummary().toLowerCase().contains(query))
        {
            return true;
        }

        return operation.servers().stream().anyMatch(server -> server.toLowerCase().contains(query));
    }

    private List<Parameter> mergeParameters(PathItem pathItem, Operation operation)
    {
        final LinkedHashMap<String, Parameter> merged = new LinkedHashMap<>();

        addParameters(merged, pathItem != null ? pathItem.getParameters() : null);
        addParameters(merged, operation.getParameters());

        return List.copyOf(merged.values());
    }

    private void addParameters(Map<String, Parameter> merged, List<Parameter> parameters)
    {
        if (parameters == null)
        {
            return;
        }

        for (Parameter parameter : parameters)
        {
            if (parameter == null)
            {
                continue;
            }
            final String key = Utils.coalesce(parameter.getIn(), "unknown") + ":" + Utils.coalesce(parameter.getName(), "param");
            merged.put(key, parameter);
        }
    }

    private LinkedHashSet<String> resolveServersForOperation(
            PathItem pathItem,
            Operation operation,
            LinkedHashSet<String> fallbackGlobal,
            String source)
    {
        if (operation.getServers() != null && !operation.getServers().isEmpty())
        {
            return collectResolvedServers(operation.getServers(), source);
        }

        if (pathItem != null && pathItem.getServers() != null && !pathItem.getServers().isEmpty())
        {
            return collectResolvedServers(pathItem.getServers(), source);
        }

        return new LinkedHashSet<>(fallbackGlobal);
    }

    private LinkedHashSet<String> collectResolvedServers(List<Server> servers, String source)
    {
        final LinkedHashSet<String> resolved = new LinkedHashSet<>();

        if (servers == null)
        {
            return resolved;
        }

        for (Server server : servers)
        {
            if (server == null || Utils.isBlank(server.getUrl()))
            {
                continue;
            }

            String url = server.getUrl();
            final Map<String, ServerVariable> variables = server.getVariables();
            if (variables != null)
            {
                for (Map.Entry<String, ServerVariable> entry : variables.entrySet())
                {
                    final ServerVariable variable = entry.getValue();
                    String value = variable != null ? variable.getDefault() : null;
                    if (Utils.isBlank(value) && variable != null)
                    {
                        final List<String> enumValues = variable.getEnum();
                        if (enumValues != null && !enumValues.isEmpty())
                        {
                            value = enumValues.get(0);
                        }
                    }
                    if (Utils.isBlank(value))
                    {
                        value = "default";
                    }
                    url = url.replace("{" + entry.getKey() + "}", value);
                }
            }

            url = toAbsoluteServer(url, source);
            resolved.add(url);
        }

        return resolved;
    }

    private String toAbsoluteServer(String serverUrl, String source)
    {
        if (Utils.isBlank(serverUrl))
        {
            return "http://localhost";
        }

        if (serverUrl.startsWith("http://") || serverUrl.startsWith("https://"))
        {
            return Utils.stripTrailingSlash(serverUrl);
        }

        if (serverUrl.startsWith("//"))
        {
            return "https:" + Utils.stripTrailingSlash(serverUrl);
        }

        if (serverUrl.startsWith("/"))
        {
            if (Utils.looksLikeHttpUrl(source))
            {
                try
                {
                    URI base = new URI(source);
                    URI resolved = new URI(base.getScheme(), base.getAuthority(), serverUrl, null, null);
                    return Utils.stripTrailingSlash(resolved.toString());
                }
                catch (URISyntaxException ignored)
                {
                    // Fall through to localhost fallback below.
                }
            }
            return Utils.stripTrailingSlash("http://localhost" + serverUrl);
        }

        if (Utils.looksLikeHttpUrl(source))
        {
            try
            {
                URI base = new URI(source);
                URI resolved = base.resolve(serverUrl);
                return Utils.stripTrailingSlash(resolved.toString());
            }
            catch (URISyntaxException ignored)
            {
                // Fall through to hostname-less fallback below.
            }
        }

        return Utils.stripTrailingSlash("http://" + serverUrl);
    }

    private String defaultServerFromSource(String source)
    {
        if (Utils.looksLikeHttpUrl(source))
        {
            try
            {
                URI uri = new URI(source);
                if (Utils.nonBlank(uri.getScheme()) && Utils.nonBlank(uri.getAuthority()))
                {
                    return Utils.stripTrailingSlash(uri.getScheme() + "://" + uri.getAuthority());
                }
            }
            catch (URISyntaxException ignored)
            {
                // Fall through to localhost fallback.
            }
        }
        return "http://localhost";
    }

    private String sourceId(String sourceLocation, String sourceLabel)
    {
        String preferred = Utils.coalesce(sourceLocation);
        if (Utils.nonBlank(preferred))
        {
            return preferred;
        }
        return "source:" + Utils.coalesce(sourceLabel, "unknown");
    }

    private void recalculateIndexes()
    {
        LinkedHashMap<String, SourceContext> recalculatedSources = new LinkedHashMap<>();
        LinkedHashMap<String, LinkedHashSet<String>> recalculatedServersBySource = new LinkedHashMap<>();

        for (SourceContext knownSource : sources.values())
        {
            if (knownSource == null || Utils.isBlank(knownSource.id()))
            {
                continue;
            }
            recalculatedSources.put(knownSource.id(), knownSource);
            recalculatedServersBySource.put(knownSource.id(), new LinkedHashSet<>());
        }

        for (OperationContext operation : operations)
        {
            if (operation == null || Utils.isBlank(operation.sourceId()))
            {
                continue;
            }

            recalculatedSources.putIfAbsent(
                    operation.sourceId(),
                    new SourceContext(
                            operation.sourceId(),
                            Utils.coalesce(operation.sourceLabel(), operation.sourceId()),
                            operation.sourceLocation()
                    )
            );
            LinkedHashSet<String> sourceServers = recalculatedServersBySource.computeIfAbsent(
                    operation.sourceId(),
                    ignored -> new LinkedHashSet<>()
            );
            if (operation.servers() != null)
            {
                sourceServers.addAll(operation.servers().stream().filter(Utils::nonBlank).toList());
            }
        }

        // Keep source insertion order stable while removing sources that no longer have operations.
        recalculatedSources.entrySet().removeIf(entry ->
                operations.stream().noneMatch(operation -> operation != null && entry.getKey().equals(operation.sourceId())));
        recalculatedServersBySource.entrySet().removeIf(entry ->
                !recalculatedSources.containsKey(entry.getKey()));

        sources.clear();
        sources.putAll(recalculatedSources);
        serversBySource.clear();
        serversBySource.putAll(recalculatedServersBySource);
        recalculateAvailableServers();
    }

    private void recalculateAvailableServers()
    {
        LinkedHashSet<String> union = new LinkedHashSet<>();
        for (LinkedHashSet<String> sourceServers : serversBySource.values())
        {
            if (sourceServers == null || sourceServers.isEmpty())
            {
                continue;
            }
            union.addAll(sourceServers.stream().filter(Utils::nonBlank).toList());
        }

        availableServers.clear();
        availableServers.addAll(union);
    }

    public record OperationContext(
            String sourceId,
            String sourceLabel,
            String sourceLocation,
            String method,
            String path,
            String summary,
            String operationId,
            List<String> tags,
            List<String> servers,
            List<Parameter> parameters,
            RequestBody requestBody,
            Operation operation)
    {
        public String tagsAsString()
        {
            return Utils.joinTags(tags);
        }

        public String serversAsString()
        {
            return String.join(" | ", servers);
        }

        public String parametersSummary()
        {
            if (parameters == null || parameters.isEmpty())
            {
                return "-";
            }

            Map<String, List<String>> grouped = new LinkedHashMap<>();
            for (Parameter parameter : parameters)
            {
                if (parameter == null)
                {
                    continue;
                }

                String location = Utils.coalesce(parameter.getIn(), "query").toLowerCase();
                String name = Utils.coalesce(parameter.getName(), "param");

                List<String> names = grouped.computeIfAbsent(location, key -> new ArrayList<>());
                if (!names.contains(name))
                {
                    names.add(name);
                }
            }

            if (grouped.isEmpty())
            {
                return "-";
            }

            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, List<String>> entry : grouped.entrySet())
            {
                List<String> names = entry.getValue();
                int previewSize = Math.min(3, names.size());
                String preview = String.join(", ", names.subList(0, previewSize));
                if (names.size() > previewSize)
                {
                    preview = preview + ", +" + (names.size() - previewSize);
                }
                parts.add(entry.getKey() + "(" + names.size() + "): " + preview);
            }
            return String.join(" | ", parts);
        }

        public String requestBodySummary()
        {
            if (requestBody != null && requestBody.getContent() != null && !requestBody.getContent().isEmpty())
            {
                String summary = String.join(", ", requestBody.getContent().keySet());
                if (Boolean.TRUE.equals(requestBody.getRequired()))
                {
                    return summary + " (required)";
                }
                return summary;
            }

            if (parameters != null)
            {
                boolean legacyBody = parameters.stream()
                        .filter(Objects::nonNull)
                        .anyMatch(parameter -> {
                            String location = Utils.coalesce(parameter.getIn(), "").toLowerCase();
                            return "body".equals(location) || "formdata".equals(location);
                        });
                if (legacyBody)
                {
                    return "legacy body/formData";
                }
            }

            return "-";
        }

        public String preferredServer(Collection<String> globalServers, String selectedServer)
        {
            if (Utils.nonBlank(selectedServer) && !"(Operation default)".equals(selectedServer))
            {
                return selectedServer;
            }
            if (!servers.isEmpty())
            {
                return servers.get(0);
            }
            if (globalServers != null)
            {
                Optional<String> first = globalServers.stream().filter(Utils::nonBlank).findFirst();
                if (first.isPresent())
                {
                    return first.get();
                }
            }
            return "http://localhost";
        }

        public OperationContext withServer(String server)
        {
            String normalizedServer = Utils.stripTrailingSlash(Utils.coalesce(server));
            List<String> replacementServers = Utils.nonBlank(normalizedServer) ? List.of(normalizedServer) : servers;
            return new OperationContext(
                    sourceId,
                    sourceLabel,
                    sourceLocation,
                    method,
                    path,
                    summary,
                    operationId,
                    tags,
                    replacementServers,
                    parameters,
                    requestBody,
                    operation
            );
        }

        public Schema<?> requestSchema()
        {
            if (requestBody == null || requestBody.getContent() == null || requestBody.getContent().isEmpty())
            {
                return null;
            }
            return requestBody.getContent().values().iterator().next().getSchema();
        }
    }

    public record SourceContext(String id, String label, String location)
    {
        @Override
        public String toString()
        {
            return Utils.coalesce(label, id);
        }
    }
}
