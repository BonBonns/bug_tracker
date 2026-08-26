package portable.provenance;

/** Provenance that entered through an out-of-band state or persistence channel. */
public record OriginRef(
    Kind kind,
    long eventId,
    long writerFunctionId,
    int writerParameterIndex,
    String channelLocation
) {
    public enum Kind {
        PERSISTED_PARAMETER,
        STATE_CHANNEL_PARAMETER,
        STATE_CHANNEL_EXTERNAL,
        /** SOURCE-R02: externally controlled bytes introduced by a file-read
         *  operation. The CORE does not know what `fread` is — a frontend source
         *  fact asserts "this operation introduced external file data into this
         *  location", and the engine merely propagates it like any other origin. */
        FILE_INPUT,
        /** Externally controlled bytes introduced by a NETWORK receive operation
         *  (recv/recvfrom/...). A DISTINCT trust boundary from FILE_INPUT: remote
         *  attacker-controlled, not local-file-controlled. Kept separate so a scan
         *  never mislabels wire data as file data (ORIGIN-KIND PURITY). */
        NETWORK_INPUT,
        /** Payload delivered to a WebExtension's externally-addressable runtime
         * message listener. Kept distinct from ordinary runtime.onMessage,
         * tab/navigation metadata, native messaging, and network bytes. */
        WEBEXT_EXTERNAL_MESSAGE_INPUT,
        /** URL metadata exposed by a WebExtension tabs event. This is kept
         *  separate from generic tab fields, runtime messages, and network bytes. */
        WEBEXT_TAB_URL_INPUT
    }
    public static OriginRef fileInput(long callId, long functionId, String location) {
        return new OriginRef(Kind.FILE_INPUT, callId, functionId, -1, location);
    }
    public static OriginRef networkInput(long callId, long functionId, String location) {
        return new OriginRef(Kind.NETWORK_INPUT, callId, functionId, -1, location);
    }
    public static OriginRef webextExternalMessageInput(long eventId, long functionId, String location) {
        return new OriginRef(Kind.WEBEXT_EXTERNAL_MESSAGE_INPUT, eventId, functionId, -1, location);
    }
    public static OriginRef webextTabUrlInput(long readId, long functionId, String location) {
        return new OriginRef(Kind.WEBEXT_TAB_URL_INPUT, readId, functionId, -1, location);
    }
    public static OriginRef persistedParameter(long writeId, long writerFunctionId, int parameterIndex, String location) {
        return new OriginRef(Kind.PERSISTED_PARAMETER, writeId, writerFunctionId, parameterIndex, location);
    }
    public static OriginRef stateChannelParameter(long writeId, long writerFunctionId, int parameterIndex, String location) {
        return new OriginRef(Kind.STATE_CHANNEL_PARAMETER, writeId, writerFunctionId, parameterIndex, location);
    }
    public static OriginRef stateChannelExternal(long readId, String location) {
        return new OriginRef(Kind.STATE_CHANNEL_EXTERNAL, readId, -1L, -1, location);
    }
}
