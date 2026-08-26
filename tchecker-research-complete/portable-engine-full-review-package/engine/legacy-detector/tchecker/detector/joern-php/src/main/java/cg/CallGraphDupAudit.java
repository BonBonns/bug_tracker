package cg;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Drop-in integrity check for the call graph -> merge-gate coupling.
 *
 * WHY THIS EXISTS
 * ---------------
 * StaticAnalysis gates every CFG merge node on  Edgetimes(n) == Edgesize(n).
 * For a non-loop merge node that equality is the ONLY way the node is ever
 * visited (the only other branch needs  Edgetimes > Edgesize && loop.contains(n)).
 * Edgesize for a call statement is seeded with  w = call2mtd.get(callsite).size().
 * call2mtd is a MultiHashMap whose add() does NOT de-duplicate, so if any
 * resolver registers the same (callsite -> callee) edge twice, w is over-counted,
 * the downstream merge's expected in-degree is too high, Edgetimes can never
 * reach it, and EVERY taint path past that merge is dropped silently (a false
 * negative with no error and no log line).
 *
 * This audit reports any callsite whose callee list contains duplicates, before
 * the taint run consumes those sizes. Gate with  WP_DUP_AUDIT=1.
 *
 * Exit behaviour is configurable:
 *   WP_DUP_AUDIT=1        -> report to stderr, keep running (observability)
 *   WP_DUP_AUDIT=strict   -> report and System.exit(3) (fail the build/run in CI)
 */
public final class CallGraphDupAudit {

	private CallGraphDupAudit() {}

	public static void run() {
		String mode = System.getenv("WP_DUP_AUDIT");
		if (mode == null || mode.isEmpty()) return;
		boolean strict = "strict".equalsIgnoreCase(mode);

		int dupCallsites = 0;
		int totalExcessEdges = 0;   // sum over callsites of (size - distinctSize) = total Edgesize inflation

		// MultiHashMap<Long,Long> exposes keySet() + get(); iterate value lists directly.
		for (Long callsite : PHPCGFactory.call2mtd.keySet()) {
			List<Long> callees = PHPCGFactory.call2mtd.get(callsite);
			if (callees == null || callees.size() < 2) continue;

			Set<Long> seen = new HashSet<Long>();
			Map<Long,Integer> mult = new HashMap<Long,Integer>();
			for (Long callee : callees) {
				if (!seen.add(callee)) {
					mult.put(callee, mult.getOrDefault(callee, 1) + 1);
				}
			}
			if (mult.isEmpty()) continue;

			dupCallsites++;
			int distinct = seen.size();
			int excess = callees.size() - distinct;   // how much w (and thus Edgesize) is inflated
			totalExcessEdges += excess;

			StringBuilder sb = new StringBuilder();
			sb.append("[DUP_AUDIT] callsite node ").append(callsite)
			  .append(": ").append(callees.size()).append(" callee edges, ")
			  .append(distinct).append(" distinct (Edgesize inflated by +").append(excess).append(")");
			for (Map.Entry<Long,Integer> e : mult.entrySet()) {
				sb.append("\n             duplicated callee ").append(e.getKey())
				  .append(" x").append(e.getValue());
			}
			System.err.println(sb.toString());
		}

		System.err.println("[DUP_AUDIT] summary: " + dupCallsites
			+ " callsite(s) with duplicate callee edges, total Edgesize inflation +"
			+ totalExcessEdges
			+ "  (each inflated non-loop merge downstream silently drops all paths past it)");

		if (strict && dupCallsites > 0) {
			System.err.println("[DUP_AUDIT] strict mode: failing (exit 3).");
			System.exit(3);
		}
	}
}
