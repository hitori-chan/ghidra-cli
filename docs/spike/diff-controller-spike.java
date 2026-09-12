// Spike: can DiffController (Ghidra 12 ProgramDiff engine) run headless,
// no Tool, on two programs in the same project?
//
// REFERENCE ONLY — not part of the build. Verified 2026-09-12 against
// Ghidra 12.1.2_DEV via `gd script run` (bridge script path). One-byte
// patch at main+4 in the second program yielded exactly one diff range
// [101040,101046] mapped to `main`. See REFACTOR-PLAN.md P8 for the API
// notes this encodes (class-form script, getDomainObject consumer must be
// non-null, TaskMonitor.DUMMY, ghidra.base.* package layout).

import ghidra.app.plugin.core.diff.DiffController;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.util.task.TaskMonitor;
// @category spike
import ghidra.app.script.GhidraScript;

public class SpikeDiff extends GhidraScript {
    @Override
    public void run() throws Exception {

Project project = getState().getProject();
DomainFile df1 = null;
DomainFile df2 = null;
for (DomainFile f : getProjectRootFolder().getFiles()) {
    if (f.getName().equals("hash")) df1 = f;
    if (f.getName().equals("hash-mod")) df2 = f;
}
if (df1 == null || df2 == null) {
    println("SPIKE MISSING programs: " + df1 + " / " + df2);
    return;
}

TaskMonitor mon = TaskMonitor.DUMMY;
Program p1 = (Program) df1.getDomainObject(this, false, false, mon);
Program p2 = (Program) df2.getDomainObject(this, false, false, mon);

AddressSet limit = new AddressSet();
for (MemoryBlock blk : p1.getMemory().getBlocks()) {
    limit.add(blk.getStart(), blk.getEnd());
}

ProgramDiffFilter f = new ProgramDiffFilter();
f.setFilter(ProgramDiffFilter.BYTE_DIFFS, true);
f.setFilter(ProgramDiffFilter.CODE_UNIT_DIFFS, true);
f.setFilter(ProgramDiffFilter.FUNCTION_DIFFS, true);
DiffController dc = new DiffController(p1, p2, limit, f, null);
AddressSetView diffs = dc.getFilteredDifferences(mon);
FunctionManager fm1 = p1.getFunctionManager();
long fnDiffs = 0;
for (ghidra.program.model.address.AddressRange r : diffs) {
    fnDiffs++;
    Address a = r.getMinAddress();
    Function fn = fm1.getFunctionAt(a);
    println("SPIKE   " + a + " (" + r + ") -> " + (fn == null ? "(no function at p1)" : fn.getName()));
}
println("SPIKE function diffs: " + fnDiffs);

f.clearAll();
f.setFilter(ProgramDiffFilter.SYMBOL_DIFFS, true);
dc = new DiffController(p1, p2, limit, f, null);
long symDiffs = 0;
for (ghidra.program.model.address.AddressRange r : dc.getFilteredDifferences(mon)) symDiffs++;
println("SPIKE symbol diffs: " + symDiffs);

println("SPIKE OK");

    }
}
