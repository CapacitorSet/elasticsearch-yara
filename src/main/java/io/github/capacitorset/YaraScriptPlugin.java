package io.github.capacitorset;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.lucene.document.Document;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.LeafReaderContext;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.ScriptPlugin;
import org.elasticsearch.script.ScriptContext;
import org.elasticsearch.script.ScriptEngine;
import org.elasticsearch.script.SearchScript;
import org.elasticsearch.search.lookup.SearchLookup;
import com.google.gson.*;

public class YaraScriptPlugin extends Plugin implements ScriptPlugin {
    @Override
    public ScriptEngine getScriptEngine(Settings settings, Collection<ScriptContext<?>> contexts) {
        return new YaraScriptEngine();
    }
}

class YaraScriptEngine implements ScriptEngine {
    @Override
    public String getType() {
        return "yara";
    }

    @Override
    public <T> T compile(String scriptName, String scriptSource, ScriptContext<T> context, Map<String, String> compileParams) {
        if (!context.equals(SearchScript.CONTEXT)) {
            throw new IllegalArgumentException(getType() + " scripts cannot be used for context [" + context.name + "]");
        }
        Gson gson = new Gson();
        SpecialPermission.check();

        SearchScript.Factory factory = (Map<String, Object> factoryParams, SearchLookup lookup) -> new SearchScript.LeafFactory() {
            // final String field;

            {
                // Initialization stuff goes here
                /*
                if (!factoryParams.containsKey("field")) {
                    throw new IllegalArgumentException("Missing parameter [field]");
                }
                field = factoryParams.get("field").toString();
                */
            }

            @Override
            public SearchScript newInstance(LeafReaderContext context) throws IOException {
                LeafReader reader = context.reader();
                return new SearchScript(factoryParams, lookup, context) {
                    int currentDocid = -1;

                    @Override
                    public void setDocument(int docid) {
                        currentDocid = docid;
                    }

                    @Override
                    public double runAsDouble() {
                        Document document;

                        assert currentDocid != -1;
                        try {
                            document = reader.document(currentDocid);
                        } catch (IOException e) {
                            e.printStackTrace();
                            return 0.0;
                        }
                        String json = document.getField("_source").binaryValue().utf8ToString();
                        System.out.println("Items:" + json);
                        // Deserialization requires reflection privileges
                        Map<String, Object> obj = AccessController.doPrivileged((PrivilegedAction<Map<String, Object>>) () -> gson.fromJson(json, HashMap.class));
                        for (Map.Entry<String, Object> entry : obj.entrySet()) {
                            System.out.println(entry.getKey() + " => " + entry.getValue().toString());
                        }
                        return 0.0d;
                    }
                };
            }

            @Override
            public boolean needs_score() {
                return false;
            }
        };
        return context.factoryClazz.cast(factory);
    }

    /*
    @Override
    public void close() {
        // optionally close resources
    }
    */
}