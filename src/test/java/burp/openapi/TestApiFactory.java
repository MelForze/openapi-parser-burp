package burp.openapi;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.JPanel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class TestApiFactory
{
    private TestApiFactory()
    {
    }

    static ApiContext apiContext()
    {
        MontoyaApi api = mock(MontoyaApi.class);
        Extension extension = mock(Extension.class);
        UserInterface userInterface = mock(UserInterface.class);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        Logging logging = mock(Logging.class);
        Repeater repeater = mock(Repeater.class);
        Intruder intruder = mock(Intruder.class);
        Scope scope = mock(Scope.class);
        Http http = mock(Http.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scanner scanner = mock(Scanner.class);
        Persistence persistence = mock(Persistence.class);
        PersistedObject extensionData = mock(PersistedObject.class);

        Registration suiteTabRegistration = mock(Registration.class);
        Registration contextMenuRegistration = mock(Registration.class);
        Registration unloadingRegistration = mock(Registration.class);
        Map<String, String> persistedStrings = new ConcurrentHashMap<>();

        when(api.extension()).thenReturn(extension);
        when(api.userInterface()).thenReturn(userInterface);
        when(api.logging()).thenReturn(logging);
        when(api.repeater()).thenReturn(repeater);
        when(api.intruder()).thenReturn(intruder);
        when(api.scope()).thenReturn(scope);
        when(api.http()).thenReturn(http);
        when(api.siteMap()).thenReturn(siteMap);
        when(api.scanner()).thenReturn(scanner);
        when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(extensionData);

        when(userInterface.createHttpRequestEditor(any(EditorOptions[].class))).thenReturn(requestEditor);
        when(userInterface.createHttpResponseEditor(any(EditorOptions[].class))).thenReturn(responseEditor);
        when(userInterface.registerSuiteTab(anyString(), any())).thenReturn(suiteTabRegistration);
        when(userInterface.registerContextMenuItemsProvider(any())).thenReturn(contextMenuRegistration);
        when(extension.registerUnloadingHandler(any(ExtensionUnloadingHandler.class))).thenReturn(unloadingRegistration);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        when(suiteTabRegistration.isRegistered()).thenReturn(true);
        when(contextMenuRegistration.isRegistered()).thenReturn(true);
        when(unloadingRegistration.isRegistered()).thenReturn(true);

        when(extensionData.getString(anyString())).thenAnswer(invocation -> persistedStrings.get(invocation.getArgument(0)));
        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            if (key != null)
            {
                persistedStrings.put(key, value);
            }
            return null;
        }).when(extensionData).setString(anyString(), anyString());
        doAnswer(invocation -> {
            persistedStrings.remove(invocation.<String>getArgument(0));
            return null;
        }).when(extensionData).deleteString(anyString());

        return new ApiContext(
                api,
                extension,
                userInterface,
                requestEditor,
                responseEditor,
                logging,
                repeater,
                intruder,
                scope,
                http,
                siteMap,
                scanner,
                persistence,
                extensionData,
                suiteTabRegistration,
                contextMenuRegistration,
                unloadingRegistration
        );
    }

    static final class ApiContext
    {
        final MontoyaApi api;
        final Extension extension;
        final UserInterface userInterface;
        final HttpRequestEditor requestEditor;
        final HttpResponseEditor responseEditor;
        final Logging logging;
        final Repeater repeater;
        final Intruder intruder;
        final Scope scope;
        final Http http;
        final SiteMap siteMap;
        final Scanner scanner;
        final Persistence persistence;
        final PersistedObject extensionData;
        final Registration suiteTabRegistration;
        final Registration contextMenuRegistration;
        final Registration unloadingRegistration;

        private ApiContext(
                MontoyaApi api,
                Extension extension,
                UserInterface userInterface,
                HttpRequestEditor requestEditor,
                HttpResponseEditor responseEditor,
                Logging logging,
                Repeater repeater,
                Intruder intruder,
                Scope scope,
                Http http,
                SiteMap siteMap,
                Scanner scanner,
                Persistence persistence,
                PersistedObject extensionData,
                Registration suiteTabRegistration,
                Registration contextMenuRegistration,
                Registration unloadingRegistration)
        {
            this.api = api;
            this.extension = extension;
            this.userInterface = userInterface;
            this.requestEditor = requestEditor;
            this.responseEditor = responseEditor;
            this.logging = logging;
            this.repeater = repeater;
            this.intruder = intruder;
            this.scope = scope;
            this.http = http;
            this.siteMap = siteMap;
            this.scanner = scanner;
            this.persistence = persistence;
            this.extensionData = extensionData;
            this.suiteTabRegistration = suiteTabRegistration;
            this.contextMenuRegistration = contextMenuRegistration;
            this.unloadingRegistration = unloadingRegistration;
        }
    }
}
