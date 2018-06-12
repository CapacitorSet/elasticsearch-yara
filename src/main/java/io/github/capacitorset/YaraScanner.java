package io.github.capacitorset;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class YaraScanner implements AutoCloseable {
    private final Runtime rt;
    File rules;
    Map<String, String> defaults;

    YaraScanner(String source) throws IOException {
        this(source, new HashMap<>());
    }

    YaraScanner(String source, Map<String, String> _defaults) throws IOException {
        rules = YaraUtils.writeToTemp(source);
        defaults = _defaults;
        rt = Runtime.getRuntime();
    }

    List<String> scan(String input, Map<String, String> params) throws IOException, InterruptedException {
        File in = YaraUtils.writeToTemp(input);
        ArrayList<String> cmdLineArray = new ArrayList<>();
        cmdLineArray.add("yara");
        // Merges params and defaults, giving priority to the former. https://stackoverflow.com/a/4702205
        Map<String, String> effectiveParams = defaults;
        effectiveParams.putAll(params);
        for (Map.Entry<String, String> entry : effectiveParams.entrySet()) {
            String k = entry.getKey();
            String v = entry.getValue();
            cmdLineArray.add("-d");
            cmdLineArray.add(k + "=" + v);
        }
        cmdLineArray.add(rules.getAbsolutePath());
        cmdLineArray.add(in.getAbsolutePath());
        Process p = rt.exec(cmdLineArray.toArray(new String[0]));
        p.waitFor();
        in.delete();
        if (p.exitValue() != 0) {
            String err = YaraUtils.convertStreamToString(p.getErrorStream());
            throw new IOException(err);
        }
        ArrayList<String> out = new ArrayList<>();
        java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter("\n");
        while (s.hasNext()) {
            out.add(s.next());
        }
        return out;
    }

    public void close() {
        this.rules.delete();
    }
}

class YaraUtils {
    static File createTempFile() throws IOException {
        File out = File.createTempFile("elasticsearch-yara-", ".tmp", new File("/tmp"));
        out.deleteOnExit();
        return out;
    }
    static File writeToTemp(String data) throws IOException {
        File tmp = createTempFile();
        FileWriter fw = new FileWriter(tmp);
        fw.write(data);
        fw.close();
        return tmp;
    }

    // https://stackoverflow.com/a/5445161
    static String convertStreamToString(InputStream is) {
        try (java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A")) {
            return s.hasNext() ? s.next() : "";
        }
    }
}
