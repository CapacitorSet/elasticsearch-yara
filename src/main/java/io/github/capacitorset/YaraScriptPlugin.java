package io.github.capacitorset;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
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
            final YaraScanner s;

            {
                // Initialization stuff goes here
                Map<String, String> stringParams = new HashMap<>();
                for (Map.Entry<String, Object> entry : factoryParams.entrySet()) {
                    String k = entry.getKey();
                    Object v = entry.getValue();
                    if (!(v instanceof String)) {
                        System.out.println("Ignoring parameter " + k + " (not a string)");
                        continue;
                    }
                    stringParams.put(k, (String) v);
                }
                try {
                    s = new YaraScanner(scriptSource, stringParams);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public SearchScript newInstance(LeafReaderContext context) {
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

                        try {
                            document = reader.document(currentDocid);
                        } catch (IOException e) {
                            e.printStackTrace();
                            return 0.0;
                        }
                        String json = document.getField("_source").binaryValue().utf8ToString();
                        // Deserialization requires reflection privileges
                        Map<String, Object> obj = AccessController.doPrivileged((PrivilegedAction<HashMap>) () -> gson.fromJson(json, HashMap.class));
                        Map<String, String> params = new HashMap<>();
                        for (Map.Entry<String, Object> entry : obj.entrySet()) {
                            String k = entry.getKey();
                            k = k.replace(".", "__");
                            Object v = entry.getValue();
                            if (v instanceof String) {
                                params.put(k, (String) v);
                            } else if (v instanceof Number) {
                                params.put(k, Integer.toString(((Number) v).intValue()));
                            } else {
                                System.out.println("[yara-search] JSON property " + k + " does not map to a string, ignored");
                            }
                        }
                        final String payload = params.getOrDefault("payload", "");
                        List<String> rules = AccessController.doPrivileged((PrivilegedAction<List<String>>) () -> {
                            try {
                                return s.scan(payload, params);
                            } catch (IOException | InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        });
                        return rules.size();
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