// Extract function and string-reference evidence inside Ghidra's JVM.
// @category BedrockLens

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class BedrockLensExtract extends GhidraScript {
    private static final class StringRecord {
        final long address;
        final String value;

        StringRecord(long address, String value) {
            this.address = address;
            this.value = value;
        }
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected one output path");
        }

        Address imageBase = currentProgram.getImageBase();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Map<Address, StringRecord> stringsByAddress = new HashMap<>();
        AddressSet stringAddresses = new AddressSet();

        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        long dataCount = 0;
        while (dataIterator.hasNext()) {
            monitor.checkCancelled();
            Data data = dataIterator.next();
            dataCount++;
            if (!data.hasStringValue() || data.getValue() == null) {
                continue;
            }
            try {
                Address address = data.getAddress();
                StringRecord record = new StringRecord(
                    address.subtract(imageBase), String.valueOf(data.getValue())
                );
                stringsByAddress.put(address, record);
                stringAddresses.add(address);
            }
            catch (RuntimeException ignored) {
                // Ignore data outside the program image address space.
            }
        }
        println("Bedrock Lens: discovered " + stringsByAddress.size() + " strings");

        Map<Long, Map<String, StringRecord>> stringsByFunction = new HashMap<>();
        AddressIterator destinations = referenceManager.getReferenceDestinationIterator(
            stringAddresses, true
        );
        long referenceCount = 0;
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            Address destination = destinations.next();
            StringRecord record = stringsByAddress.get(destination);
            if (record == null) {
                continue;
            }
            ReferenceIterator references = referenceManager.getReferencesTo(destination);
            while (references.hasNext()) {
                Reference reference = references.next();
                referenceCount++;
                Function function = functionManager.getFunctionContaining(
                    reference.getFromAddress()
                );
                if (function == null || function.isExternal()) {
                    continue;
                }
                long functionRva;
                try {
                    functionRva = function.getEntryPoint().subtract(imageBase);
                }
                catch (RuntimeException ignored) {
                    continue;
                }
                Map<String, StringRecord> records = stringsByFunction.computeIfAbsent(
                    functionRva, ignored -> new LinkedHashMap<>()
                );
                records.put(record.address + "\u0000" + record.value, record);
            }
        }
        println("Bedrock Lens: matched " + referenceCount + " string references");

        Path output = Path.of(arguments[0]);
        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            writer.write("V\t1\n");
            FunctionIterator functions = functionManager.getFunctions(true);
            long functionCount = 0;
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                if (function.isExternal()) {
                    continue;
                }
                long rva;
                try {
                    rva = function.getEntryPoint().subtract(imageBase);
                }
                catch (RuntimeException ignored) {
                    continue;
                }
                Namespace namespace = function.getParentNamespace();
                writer.write(
                    "F\t" + rva + "\t" + function.getBody().getNumAddresses() + "\t" +
                    function.getParameterCount() + "\t" + encode(function.getName()) + "\t" +
                    encode(namespace == null ? "" : namespace.getName(true)) + "\n"
                );
                Map<String, StringRecord> rawRecords = stringsByFunction.get(rva);
                if (rawRecords != null) {
                    List<StringRecord> records = new ArrayList<>(rawRecords.values());
                    records.sort(
                        Comparator.comparingLong((StringRecord record) -> record.address)
                            .thenComparing(record -> record.value)
                    );
                    for (StringRecord record : records) {
                        writer.write(
                            "S\t" + rva + "\t" + record.address + "\t" +
                            encode(record.value) + "\n"
                        );
                    }
                }
                functionCount++;
                if (functionCount % 10000 == 0) {
                    println("Bedrock Lens: exported " + functionCount + " functions");
                }
            }
            println("Bedrock Lens: exported " + functionCount + " functions total");
        }
    }

    private static String encode(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
