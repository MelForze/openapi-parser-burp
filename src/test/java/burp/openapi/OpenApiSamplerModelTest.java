package burp.openapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.servers.ServerVariables;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class OpenApiSamplerModelTest
{
    @Test
    void loadMergesOperationsAcrossSpecsWithoutDuplicates()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        OpenAPI users = singleGetSpec("https://api.one.test", "/users", "usersList", "List users");
        OpenAPI orders = singleGetSpec("https://api.two.test", "/orders", "ordersList", "List orders");

        model.load(users, "https://api.one.test/openapi.json");
        model.load(orders, "https://api.two.test/openapi.json");
        model.load(users, "https://api.one.test/openapi.json");

        assertEquals(2, model.operations().size());
        assertEquals(2, model.availableServers().size());
        assertTrue(model.availableServers().contains("https://api.one.test"));
        assertTrue(model.availableServers().contains("https://api.two.test"));
    }

    @Test
    void filterSupportsServerSelectionAndTextFields()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        Operation userOperation = new Operation()
                .operationId("usersList")
                .summary("List users")
                .tags(List.of("users", "admin"))
                .addParametersItem(new Parameter().in("query").name("role").example("admin"));

        RequestBody requestBody = new RequestBody();
        requestBody.setContent(new Content().addMediaType("application/json", new MediaType().schema(new ObjectSchema())));
        userOperation.setRequestBody(requestBody);

        PathItem usersPath = new PathItem().get(userOperation);
        PathItem ordersPath = new PathItem().get(new Operation()
                .operationId("ordersList")
                .summary("List orders")
                .tags(List.of("orders")));

        OpenAPI spec1 = new OpenAPI()
                .servers(List.of(new Server().url("https://api.one.test")))
                .paths(new Paths()
                        .addPathItem("/users", usersPath)
                        .addPathItem("/orders", ordersPath));
        model.load(spec1, "https://api.one.test/openapi.json");

        OpenAPI spec2 = singleGetSpec("https://api.two.test", "/audit", "auditList", "List audit");
        model.load(spec2, "https://api.two.test/openapi.json");

        assertEquals(3, model.filter("", null).size());
        assertEquals(2, model.filter("", "https://api.one.test").size());
        assertEquals(1, model.filter("audit", "https://api.two.test").size());
        assertEquals(1, model.filter("users", "https://api.one.test").size());
        assertEquals(1, model.filter("userslist", "https://api.one.test").size());
        assertEquals(1, model.filter("admin", "https://api.one.test").size());
        assertEquals(1, model.filter("query(1): role", "https://api.one.test").size());
        assertEquals(1, model.filter("application/json", "https://api.one.test").size());
    }

    @Test
    void dedupeIsScopedPerSourceAndSameOperationInDifferentSourcesIsPreserved()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        OpenAPI users = singleGetSpec("https://api.one.test", "/users", "usersList", "List users");

        model.load(users, "https://api.one.test/openapi.json", "one");
        model.load(users, "https://api.one.test/openapi.json", "one");
        model.load(users, "https://api.two.test/openapi.json", "two");

        assertEquals(2, model.operations().size());
        assertEquals(
                1,
                model.operations().stream().filter(op -> "https://api.one.test/openapi.json".equals(op.sourceId())).count()
        );
        assertEquals(
                1,
                model.operations().stream().filter(op -> "https://api.two.test/openapi.json".equals(op.sourceId())).count()
        );
    }

    @Test
    void filterSupportsSourceIsolationAndSourceScopedServers()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        model.load(singleGetSpec("https://api.one.test", "/users", "users", "Users"), "https://api.one.test/openapi.json", "one");
        model.load(singleGetSpec("https://api.two.test", "/orders", "orders", "Orders"), "https://api.two.test/openapi.json", "two");

        assertEquals(2, model.operations().size());
        assertEquals(1, model.filter("", null, "https://api.one.test/openapi.json").size());
        assertEquals(1, model.filter("", null, "https://api.two.test/openapi.json").size());
        assertEquals("/users", model.filter("", null, "https://api.one.test/openapi.json").get(0).path());

        assertEquals(List.of("https://api.one.test"), model.availableServers("https://api.one.test/openapi.json"));
        assertEquals(List.of("https://api.two.test"), model.availableServers("https://api.two.test/openapi.json"));
        assertEquals(2, model.availableSources().size());
    }

    @Test
    void loadResolvesServerVariablesAndRelativeUrls()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        ServerVariables variables = new ServerVariables();
        variables.addServerVariable("env", new io.swagger.v3.oas.models.servers.ServerVariable()._default("prod"));
        variables.addServerVariable("version", new io.swagger.v3.oas.models.servers.ServerVariable()._enum(List.of("v1", "v2")));

        OpenAPI openAPI = new OpenAPI();
        openAPI.setServers(List.of(
                new Server().url("https://{env}.example.com/{version}").variables(variables),
                new Server().url("/api"),
                new Server().url("//cdn.example.com/base"),
                new Server().url("relative/base")
        ));
        openAPI.setPaths(new Paths().addPathItem("/users", new PathItem().get(new Operation().summary("Users"))));

        model.load(openAPI, "https://docs.example.com/specs/openapi.json");

        assertTrue(model.availableServers().contains("https://prod.example.com/v1"));
        assertTrue(model.availableServers().contains("https://docs.example.com/api"));
        assertTrue(model.availableServers().contains("https://cdn.example.com/base"));
        assertTrue(model.availableServers().contains("https://docs.example.com/specs/relative/base"));
    }

    @Test
    void operationsAreExpandedPerServerWhenMultipleServersAreAvailable()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        OpenAPI openAPI = new OpenAPI()
                .servers(List.of(
                        new Server().url("https://api.one.test"),
                        new Server().url("https://api.two.test")
                ))
                .paths(new Paths().addPathItem("/users", new PathItem().get(new Operation().summary("Users"))));

        model.load(openAPI, "https://docs.example.com/openapi.json");

        assertEquals(2, model.operations().size());
        assertEquals(List.of("https://api.one.test"), model.operations().get(0).servers());
        assertEquals(List.of("https://api.two.test"), model.operations().get(1).servers());
    }

    @Test
    void loadFallsBackToSourceHostWhenNoServerDefined()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        OpenAPI openAPI = new OpenAPI();
        openAPI.setPaths(new Paths().addPathItem("/health", new PathItem().get(new Operation().summary("Health"))));

        model.load(openAPI, "https://api.source.test/openapi.json");

        assertEquals(1, model.availableServers().size());
        assertEquals("https://api.source.test", model.availableServers().get(0));
    }

    @Test
    void operationServerOverridesPathAndGlobalServers()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        PathItem pathItem = new PathItem();
        pathItem.setServers(List.of(new Server().url("https://path.example")));
        pathItem.setGet(new Operation()
                .summary("Path-level")
                .operationId("pathLevel")
                .servers(List.of(new Server().url("https://operation.example"))));

        OpenAPI openAPI = new OpenAPI()
                .servers(List.of(new Server().url("https://global.example")))
                .paths(new Paths().addPathItem("/scope", pathItem));

        model.load(openAPI, "https://global.example/openapi.json");

        OpenApiSamplerModel.OperationContext context = model.operations().get(0);
        assertEquals(List.of("https://operation.example"), context.servers());
    }

    @Test
    void summaryTextIsRepairedWhenMojibakeDetected()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        OpenAPI openAPI = new OpenAPI()
                .servers(List.of(new Server().url("https://api.example")))
                .paths(new Paths().addPathItem(
                        "/items",
                        new PathItem().get(new Operation().summary("РњРµС‚РѕРґ СЃРѕР·РґР°РЅРёСЏ"))
                ));

        model.load(openAPI, "https://api.example/openapi.json");

        assertEquals("Метод создания", model.operations().get(0).summary());
    }

    @Test
    void pathParametersAreMergedAndOperationOverridesPathParameter()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();

        Parameter pathLevelId = new Parameter().name("id").in("path").example("from-path");
        Parameter operationLevelId = new Parameter().name("id").in("path").example("from-operation");
        Parameter queryParam = new Parameter().name("expand").in("query").example("true");

        Operation getOperation = new Operation()
                .summary("Get by id")
                .operationId("getById")
                .parameters(List.of(operationLevelId, queryParam));

        PathItem pathItem = new PathItem()
                .get(getOperation)
                .parameters(List.of(pathLevelId));

        OpenAPI openAPI = new OpenAPI()
                .servers(List.of(new Server().url("https://api.example")))
                .paths(new Paths().addPathItem("/users/{id}", pathItem));

        model.load(openAPI, "https://api.example/openapi.json");

        OpenApiSamplerModel.OperationContext context = model.operations().get(0);
        assertEquals(2, context.parameters().size());
        Map<String, String> paramValues = new LinkedHashMap<>();
        for (Parameter parameter : context.parameters())
        {
            paramValues.put(parameter.getName(), String.valueOf(parameter.getExample()));
        }
        assertEquals("from-operation", paramValues.get("id"));
        assertEquals("true", paramValues.get("expand"));
    }

    @Test
    void operationContextSummariesAreGenerated()
    {
        Schema<?> bodySchema = new ObjectSchema().addProperty("username", new StringSchema());
        RequestBody requestBody = new RequestBody();
        requestBody.setRequired(true);
        requestBody.setContent(new Content().addMediaType("application/json", new MediaType().schema(bodySchema)));

        List<Parameter> parameters = List.of(
                new Parameter().in("query").name("a"),
                new Parameter().in("query").name("b"),
                new Parameter().in("query").name("c"),
                new Parameter().in("query").name("d"),
                new Parameter().in("header").name("x-id")
        );

        OpenApiSamplerModel.OperationContext context = new OpenApiSamplerModel.OperationContext(
                "source:test",
                "test-source",
                "https://api.example/openapi.json",
                "POST",
                "/users",
                "Create user",
                "createUser",
                List.of("users", "admin"),
                List.of("https://api.example"),
                parameters,
                requestBody,
                new Operation()
        );

        assertEquals("users, admin", context.tagsAsString());
        assertEquals("https://api.example", context.serversAsString());
        assertTrue(context.parametersSummary().contains("query(4): a, b, c, +1"));
        assertTrue(context.parametersSummary().contains("header(1): x-id"));
        assertEquals("application/json (required)", context.requestBodySummary());
        assertNotNull(context.requestSchema());
    }

    @Test
    void requestBodySummarySupportsLegacyBodyAndFormData()
    {
        List<Parameter> legacyParameters = List.of(
                new Parameter().in("body").name("payload"),
                new Parameter().in("formData").name("file")
        );

        OpenApiSamplerModel.OperationContext context = new OpenApiSamplerModel.OperationContext(
                "source:test",
                "test-source",
                "https://api.example/openapi.json",
                "POST",
                "/legacy",
                "Legacy",
                "legacy",
                List.of(),
                List.of(),
                legacyParameters,
                null,
                new Operation()
        );

        assertEquals("legacy body/formData", context.requestBodySummary());
    }

    @Test
    void preferredServerSelectionWorks()
    {
        OpenApiSamplerModel.OperationContext context = new OpenApiSamplerModel.OperationContext(
                "source:test",
                "test-source",
                "https://api.example/openapi.json",
                "GET",
                "/users",
                "Users",
                "users",
                List.of(),
                List.of("https://operation-server"),
                List.of(),
                null,
                new Operation()
        );

        assertEquals("https://selected-server", context.preferredServer(List.of("https://global"), "https://selected-server"));
        assertEquals("https://operation-server", context.preferredServer(List.of("https://global"), "(Operation default)"));
        assertEquals("https://global", new OpenApiSamplerModel.OperationContext(
                "source:test",
                "test-source",
                "https://api.example/openapi.json",
                "GET", "/users", "Users", "users", List.of(), List.of(), List.of(), null, new Operation()
        ).preferredServer(List.of("https://global"), "(Operation default)"));
    }

    @Test
    void removeOperationsAndClearResetState()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        OpenAPI openAPI = new OpenAPI()
                .servers(List.of(new Server().url("https://api.example")))
                .paths(new Paths()
                        .addPathItem("/a", new PathItem().get(new Operation().summary("A")))
                        .addPathItem("/b", new PathItem().get(new Operation().summary("B"))));

        model.load(openAPI, "https://api.example/openapi.json");
        assertEquals(2, model.operations().size());

        int removed = model.removeOperations(List.of(model.operations().get(0)));
        assertEquals(1, removed);
        assertEquals(1, model.operations().size());

        model.clear();
        assertEquals(0, model.operations().size());
        assertEquals(0, model.availableServers().size());
        assertNull(model.openAPI());
        assertNull(model.sourceLocation());
    }

    @Test
    void operationsAreSortedByPathThenMethod()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        Paths paths = new Paths();

        PathItem zPath = new PathItem();
        zPath.setPost(new Operation().summary("Z post"));
        zPath.setGet(new Operation().summary("Z get"));
        paths.addPathItem("/z", zPath);

        PathItem aPath = new PathItem();
        aPath.setPost(new Operation().summary("A post"));
        aPath.setGet(new Operation().summary("A get"));
        paths.addPathItem("/a", aPath);

        model.load(new OpenAPI().servers(List.of(new Server().url("https://api.example"))).paths(paths), "https://api.example/openapi.json");

        List<OpenApiSamplerModel.OperationContext> operations = model.operations();
        assertEquals("/a", operations.get(0).path());
        assertEquals("GET", operations.get(0).method());
        assertEquals("/a", operations.get(1).path());
        assertEquals("POST", operations.get(1).method());
        assertEquals("/z", operations.get(2).path());
        assertEquals("GET", operations.get(2).method());
    }

    @Test
    void filterByServerIgnoresOperationDefaultPseudoValue()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        model.load(singleGetSpec("https://api.example", "/users", "users", "Users"), "https://api.example/openapi.json");

        assertEquals(1, model.filter("", "(Operation default)").size());
        assertFalse(model.filter("", "https://another.example").size() > 0);
    }

    @Test
    void selectedOperationsCanReplaceServer()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        model.load(singleGetSpec("https://api.example", "/users", "users", "Users"), "https://api.example/openapi.json");
        model.load(singleGetSpec("https://api.example", "/orders", "orders", "Orders"), "https://api.example/openapi.json");

        int updated = model.replaceServer(model.operations(), "http://127.0.0.1:18080/");

        assertEquals(2, updated);
        assertEquals(List.of("http://127.0.0.1:18080"), model.availableServers());
        assertEquals(2, model.filter("", "http://127.0.0.1:18080").size());
        assertTrue(model.operations().stream()
                .allMatch(operation -> operation.servers().equals(List.of("http://127.0.0.1:18080"))));
    }

    @Test
    void operationsAccessorReturnsImmutableSnapshotNotLiveView()
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        model.load(singleGetSpec("https://api.one.test", "/a", "a", "A"), "https://api.one.test/openapi.json");

        List<OpenApiSamplerModel.OperationContext> snapshot = model.operations();
        int sizeBefore = snapshot.size();

        // A previously returned list must not change when the model is mutated afterwards, otherwise a
        // worker thread iterating it can hit ConcurrentModificationException while the EDT loads a spec.
        model.load(singleGetSpec("https://api.two.test", "/b", "b", "B"), "https://api.two.test/openapi.json");

        assertEquals(sizeBefore, snapshot.size());
        assertEquals(2, model.operations().size());
    }

    @Test
    void concurrentReadsAndLoadsDoNotThrow() throws Exception
    {
        OpenApiSamplerModel model = new OpenApiSamplerModel();
        model.load(singleGetSpec("https://seed.test", "/seed", "seed", "Seed"), "https://seed.test/openapi.json");

        AtomicReference<Throwable> error = new AtomicReference<>();
        AtomicBoolean stop = new AtomicBoolean(false);

        Thread writer = new Thread(() -> {
            int i = 0;
            while (!stop.get() && error.get() == null)
            {
                try
                {
                    int bucket = i % 5;
                    model.load(singleGetSpec("https://w.test/" + bucket, "/p" + bucket, "op" + bucket, "S"),
                            "https://w.test/" + bucket + "/openapi.json");
                    if (i % 50 == 0)
                    {
                        model.clear();
                    }
                    i++;
                }
                catch (Throwable t)
                {
                    error.set(t);
                }
            }
        });

        Thread reader = new Thread(() -> {
            while (!stop.get() && error.get() == null)
            {
                try
                {
                    for (OpenApiSamplerModel.OperationContext op : model.operations())
                    {
                        op.path();
                    }
                    model.availableServers().forEach(String::length);
                    model.availableServers("missing").size();
                    model.availableSources().size();
                    model.filter("", "(Operation default)", "");
                }
                catch (Throwable t)
                {
                    error.set(t);
                }
            }
        });

        writer.start();
        reader.start();
        Thread.sleep(250L);
        stop.set(true);
        writer.join(2000L);
        reader.join(2000L);

        if (error.get() != null)
        {
            throw new AssertionError("concurrent model access threw: " + error.get(), error.get());
        }
    }

    private OpenAPI singleGetSpec(String server, String path, String operationId, String summary)
    {
        Operation operation = new Operation()
                .operationId(operationId)
                .summary(summary)
                .addTagsItem("seed")
                .addParametersItem(new Parameter().in("query").name("q").example("x"));

        PathItem pathItem = new PathItem().get(operation);

        return new OpenAPI()
                .servers(List.of(new Server().url(server)))
                .paths(new Paths().addPathItem(path, pathItem));
    }
}
