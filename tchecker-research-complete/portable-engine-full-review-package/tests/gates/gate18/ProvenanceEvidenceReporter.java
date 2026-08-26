package cg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Read-only downstream view of return provenance.
 *
 * IMPORTANT: uncertain provenance is evidence only.  AMBIGUOUS/UNKNOWN records
 * never become hard source facts and this class never mutates PHPCGFactory's
 * propagation maps.
 */
public final class ProvenanceEvidenceReporter {
    private ProvenanceEvidenceReporter() {}

    public enum Status { PROVEN, MAY, UNKNOWN, NONE }

    public static final class Record {
        public final long functionId;
        public final Status status;
        public final String resolution;
        public final List<Integer> parameterPositions;
        public final boolean hardSource;

        Record(long functionId, Status status, String resolution,
               List<Integer> parameterPositions, boolean hardSource) {
            this.functionId = functionId;
            this.status = status;
            this.resolution = resolution;
            this.parameterPositions = Collections.unmodifiableList(parameterPositions);
            this.hardSource = hardSource;
        }

        public String render() {
            return "ProvenanceEvidence: function=" + functionId
                + " status=" + status
                + " resolution=" + resolution
                + " positions=" + parameterPositions
                + " hard_source=" + hardSource;
        }
    }

    private static List<Integer> sorted(Set<Integer> in) {
        ArrayList<Integer> out = new ArrayList<Integer>();
        if (in != null) out.addAll(in);
        Collections.sort(out);
        return out;
    }

    /** Return a read-only evidence classification for one function. */
    public static Record forFunction(long fid) {
        Set<Integer> hard = PHPCGFactory.returnTaintPositions.get(fid);
        boolean hardAnalyzed = PHPCGFactory.returnTaintAnalyzed.contains(fid);
        if (hardAnalyzed && hard != null && !hard.isEmpty()) {
            return new Record(fid, Status.PROVEN, "EXACT", sorted(hard), true);
        }

        String mayResolution = PHPCGFactory.returnMayTaintResolution.get(fid);
        if (mayResolution != null) {
            Set<Integer> may = PHPCGFactory.returnMayTaintPositions.get(fid);
            if ("UNKNOWN".equals(mayResolution)) {
                return new Record(fid, Status.UNKNOWN, "UNKNOWN", sorted(may), false);
            }
            // AMBIGUOUS and any future non-hard resolution remain MAY evidence.
            return new Record(fid, Status.MAY, mayResolution, sorted(may), false);
        }

        return new Record(fid, Status.NONE, "NONE", Collections.<Integer>emptyList(), false);
    }
}
