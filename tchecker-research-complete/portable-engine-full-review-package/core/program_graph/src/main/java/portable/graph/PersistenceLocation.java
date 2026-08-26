package portable.graph;

/** Language-neutral identity for a durable/state channel location. */
public record PersistenceLocation(String domain, String objectKey, String slotKey) {
    public PersistenceLocation {
        domain = domain == null ? "" : domain;
        objectKey = objectKey == null ? "" : objectKey;
        slotKey = slotKey == null ? "" : slotKey;
    }
    public String stableKey() { return domain + ":" + objectKey + ":" + slotKey; }
}
