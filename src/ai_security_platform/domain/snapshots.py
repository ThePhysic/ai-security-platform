from enum import StrEnum


class ProvenanceKind(StrEnum):
    LOCAL_CLI = "local_cli"
    CI_CHECKOUT = "ci_checkout"


class RetentionState(StrEnum):
    PUBLISHED = "published"
    UNAVAILABLE = "unavailable"
