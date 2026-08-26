package portable.consumer;

/** Aggregate state of typed path relations supplied to the consumer. */
public enum RelationDisposition {
    ALL_ESTABLISHED,
    POSSIBLE_RELATION,
    ABSTAINED_RELATION,
    NO_RELATIONS
}
