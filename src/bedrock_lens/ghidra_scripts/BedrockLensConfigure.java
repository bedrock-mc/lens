// Configure a bounded analysis profile suitable for corpus indexing and BSim.
// @category BedrockLens

import java.util.Locale;
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class BedrockLensConfigure extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        disable(options, "Decompiler Parameter ID");
        disable(options, "Decompiler Switch Analysis");
        disable(options, "Non-Returning Functions - Discovered");
        disable(options, "Stack");
        disable(options, "DWARF");

        for (String option : options.keySet()) {
            String normalized = option.toLowerCase(Locale.ROOT);
            if (normalized.contains("x86") && normalized.contains("constant")
                    && !option.contains(".")) {
                disable(options, option);
            }
        }

        enable(options, "Shared Return Calls");
        enable(options, "Function Start Search");
    }

    private void disable(Map<String, String> options, String name) {
        if (options.containsKey(name)) {
            println("Bedrock Lens: disabling analyzer " + name);
            setAnalysisOption(currentProgram, name, "false");
        }
    }

    private void enable(Map<String, String> options, String name) {
        if (options.containsKey(name)) {
            println("Bedrock Lens: enabling analyzer " + name);
            setAnalysisOption(currentProgram, name, "true");
        }
    }
}
