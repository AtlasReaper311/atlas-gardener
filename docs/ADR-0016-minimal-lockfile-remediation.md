# ADR-0016 minimal transitive lockfile remediation

The first live ADR-0016 controller proof showed that pinned npm regeneration could normalize unrelated lockfile metadata while performing a valid transitive security update. Producer and consumer digests matched, so the authority and integrity boundary held, but the generated patch was broader than necessary.

For candidates containing only transitive graph operations, Gardener now treats npm as the resolver of record and then copies only the exact admitted transitive package nodes onto the exact audited lockfile preimage. The resulting minimal lockfile must still match the producer digest and pass the bounded OSV postcondition before a ChangePlan can be created.

Direct dependency and direct-ancestor operations retain full deterministic regeneration because those changes can legitimately alter a wider graph. The minimal overlay fails closed for noncanonical npm JSON, legacy top-level dependency maps, missing admitted nodes, duplicate paths, or any unexpected package.json rewrite.
