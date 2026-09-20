"""Compose a Threat Composer threat statement from its structured elements.

Threat Composer renders a statement as
``A/an [threat_source] [prerequisites] can [threat_action], which leads to
[threat_impact]``. The server stores the four elements separately and composes
the ``statement`` string from them.

This module centralises that composition so the ``add`` and ``update`` paths
stay identical, and it fixes a long-standing wording bug: the template used to
hard-prefix ``"A "`` even when ``threat_source`` already began with an article
(e.g. "A misdirected agent"), producing a doubled "A A ..." statement. We now
emit the article only when the source does not already start with one.
"""

import re

_LEADING_ARTICLE = re.compile(r"^\s*(an?)\b", re.IGNORECASE)

# Common English cases where the article does not match the first letter,
# because "a" vs "an" follows sound, not spelling.
# Consonant-spelled words with a silent "h" that take "an".
_TAKES_AN_DESPITE_CONSONANT = ("hour", "honest", "honor", "honour", "heir")
# Vowel-spelled words pronounced with a leading consonant sound ("y"/"w")
# that take "a".
_TAKES_A_DESPITE_VOWEL = ("uni", "use", "usu", "eu", "ewe", "one", "once")


def _needs_an(word: str) -> bool:
    """Return whether ``word`` takes the article "an" (sound-based)."""
    lowered = word.lower()
    if lowered.startswith(_TAKES_AN_DESPITE_CONSONANT):
        return True
    if lowered.startswith(_TAKES_A_DESPITE_VOWEL):
        return False
    return lowered[0] in "aeiou"


def _article_for(threat_source: str) -> str:
    """Return the leading article to prepend, or '' if the source has one.

    Chooses "An" before a vowel sound and "A" otherwise. Returns an empty
    string when ``threat_source`` already starts with "a"/"an" so the article
    is not duplicated.
    """
    source = (threat_source or "").strip()
    if not source:
        return ""
    if _LEADING_ARTICLE.match(source):
        return ""
    first_word = source.split()[0]
    return "An" if _needs_an(first_word) else "A"


def compose_statement(
    threat_source: str,
    prerequisites: str,
    threat_action: str,
    threat_impact: str,
) -> str:
    """Compose the threat statement, collapsing repeated whitespace."""
    article = _article_for(threat_source)
    parts = [
        article,
        (threat_source or "").strip(),
        (prerequisites or "").strip(),
        "can",
        (threat_action or "").strip(),
    ]
    lead = " ".join(p for p in parts if p)
    statement = f"{lead}, which leads to {(threat_impact or '').strip()}"
    # Collapse any runs of whitespace introduced by empty elements.
    return re.sub(r"\s+", " ", statement).strip()
