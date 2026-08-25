"""Monotonic identifier generation for the threat modeling collections.

Identifiers must never be reused. The obvious ``f"{prefix}{len(store) + 1:03d}"``
reuses an id as soon as anything is deleted, which silently overwrites a
surviving record: with TA001-TA012 present, deleting TA005 makes the next add
produce TA012 and replace the existing entry.

That matters beyond the immediate overwrite because ids are referenced from
elsewhere: UserPersona.threat_actor_overlay stores threat actor ids, mitigation
links store threat ids, and exported reports quote ids. A reused id silently re-points those references.

Counters are per prefix and only ever increase within a session. The current
records are consulted only to recover a high-water mark, so ids stay unique even
if a store was populated by some other route (for example a default library).
"""

import re
import threading
from typing import Any, Dict, Mapping

# prefix -> highest number issued so far
_counters: Dict[str, int] = {}
_lock = threading.Lock()


def next_id(existing: Mapping[str, Any], prefix: str) -> str:
    """Return the next never-before-issued id for a prefix.

    Args:
        existing: Current records keyed by id, consulted only to recover the
            high-water mark (for example after loading a default library)
        prefix: Id prefix, for example "TA", "C" or "DP"

    Returns:
        A new id of the form ``{prefix}{number:03d}``
    """
    pattern = re.compile(rf"{re.escape(prefix)}(\d+)$")

    with _lock:
        highest = _counters.get(prefix, 0)

        for key in existing:
            match = pattern.fullmatch(str(key))
            if match:
                highest = max(highest, int(match.group(1)))

        highest += 1
        _counters[prefix] = highest

    return f"{prefix}{highest:03d}"


def reset_id_counters(prefix: str = None) -> None:
    """Reset the counters. Only for starting a genuinely new threat model.

    Args:
        prefix: Reset just this prefix, or every prefix when omitted
    """
    with _lock:
        if prefix is None:
            _counters.clear()
        else:
            _counters.pop(prefix, None)
