package portable.graph;

/** Language-neutral reference to a semantic value. */
public record ValueRef(Kind kind, long referencedId, String code) {
    public enum Kind { PARAMETER, LOCAL, CALL, PERSISTENCE_READ, STATE_CHANNEL_READ, STATE_READ, SELF, FUNCTION, EXTERNAL_INPUT, CONSTANT, UNKNOWN }

    public static ValueRef parameter(long parameterId, String code) {
        return new ValueRef(Kind.PARAMETER, parameterId, code);
    }
    public static ValueRef local(long localId, String code) {
        return new ValueRef(Kind.LOCAL, localId, code);
    }
    public static ValueRef call(long callId, String code) {
        return new ValueRef(Kind.CALL, callId, code);
    }
    public static ValueRef persistenceRead(long readId, String code) {
        return new ValueRef(Kind.PERSISTENCE_READ, readId, code);
    }
    public static ValueRef stateChannelRead(long readId, String code) {
        return new ValueRef(Kind.STATE_CHANNEL_READ, readId, code);
    }
    public static ValueRef stateRead(long readId, String code) {
        return new ValueRef(Kind.STATE_READ, readId, code);
    }
    /** SOURCE-R02e: a value introduced by an external source operation. Carried
     *  as an ordinary definition so reaching definitions can kill or preserve it. */
    public static ValueRef externalInput(long sourceId, String code) {
        return new ValueRef(Kind.EXTERNAL_INPUT, sourceId, code);
    }

    /** A callable value: a reference to a function used as data (id = the target
     *  method id). It carries no data origin of its own — a function literal is
     *  not derived from any parameter — but it makes the callee of a higher-order
     *  call statically identifiable. */
    public static ValueRef function(long methodId, String code) {
        return new ValueRef(Kind.FUNCTION, methodId, code);
    }

    /** The receiver object of the enclosing method (id = the method id). */
    public static ValueRef self(long methodId) {
        return new ValueRef(Kind.SELF, methodId, "this");
    }
    public static ValueRef constant(String code) {
        return new ValueRef(Kind.CONSTANT, -1L, code);
    }
    public static ValueRef unknown(String code) {
        return new ValueRef(Kind.UNKNOWN, -1L, code);
    }
}
