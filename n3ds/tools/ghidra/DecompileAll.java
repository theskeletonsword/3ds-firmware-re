// Bulk decompiler for headless Ghidra. Args: <outdir> [names.tsv]
// names.tsv: "0xADDR<TAB>name[<TAB>func|data]" - applied (function/label created if missing) BEFORE decompiling, so the C output uses our symbol names.
// Output: <outdir>/<addr8>.c per function (existing files are skipped -> resumable) and <outdir>/index.tsv (addr, name, size, status, lines).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File out = new File(a[0]); out.mkdirs();
        int named = 0, created = 0;
        if (a.length > 1 && new File(a[1]).exists()) {
            for (String l : Files.readAllLines(Paths.get(a[1]))) {
                String[] p = l.split("\t");
                if (p.length < 2) continue;
                try {
                    Address ad = toAddr(Long.decode(p[0].trim()));
                    if (ad == null || currentProgram.getMemory().getBlock(ad) == null) continue;
                    String nm = p[1].replaceAll("[^A-Za-z0-9_]", "_");
                    String kind = p.length > 2 ? p[2].trim() : "func";
                    if ("data".equals(kind)) {
                        createLabel(ad, nm, true, SourceType.USER_DEFINED);
                        named++;
                    } else {
                        Function f = getFunctionAt(ad);
                        if (f == null) { disassemble(ad); f = createFunction(ad, nm); if (f != null) created++; }
                        else f.setName(nm, SourceType.USER_DEFINED);
                        if (f != null) named++;
                    }
                } catch (Exception e) { /* skip bad rows */ }
            }
        }
        if (currentProgram.getFunctionManager().getFunctionCount() == 0) {
            Address entry = currentProgram.getMemory().getMinAddress();
            if (entry != null) {
                disassemble(entry);
                if (createFunction(entry, null) != null) created++;
            }
        }
        if (created > 0) analyzeChanges(currentProgram);
        println("named functions: " + named);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        StringBuilder idx = new StringBuilder("addr\tname\tsize\tstatus\tlines\n");
        int done = 0, fail = 0, skipped = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            long off = f.getEntryPoint().getOffset();
            File of = new File(out, String.format("%08x.c", off));
            long size = f.getBody().getNumAddresses();
            if (of.exists()) { skipped++; idx.append(String.format("0x%08x\t%s\t%d\texisting\t-\n", off, f.getName(), size)); continue; }
            DecompileResults r = di.decompileFunction(f, 40, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                String c = r.getDecompiledFunction().getC();
                try (PrintWriter w = new PrintWriter(of)) {
                    w.println("// " + f.getName() + " @ 0x" + Long.toHexString(off) + "  size " + size + " bytes  (headless Ghidra " + currentProgram.getLanguageID() + ")");
                    w.print(c);
                }
                done++; idx.append(String.format("0x%08x\t%s\t%d\tok\t%d\n", off, f.getName(), size, c.split("\n").length));
            } else {
                fail++; idx.append(String.format("0x%08x\t%s\t%d\tfail\t%s\n", off, f.getName(), size, r == null ? "null" : r.getErrorMessage()));
            }
        }
        Files.write(Paths.get(out.getPath(), "index.tsv"), idx.toString().getBytes());
        println("decompiled=" + done + " failed=" + fail + " existing=" + skipped);
    }
}
