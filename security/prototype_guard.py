"""Prototype-pollution guard utilities.

The helpers in this module treat user supplied objects (configuration,
JSON payloads, nested component props, ...) as untrusted.  In a
JavaScript runtime the keys ``__proto__``, ``constructor`` and
``prototype`` can be used to walk from a plain object onto
``Object.prototype`` and poison every object created afterwards.

Python does not have the same prototype chain, but the same payloads
reach this code path (shared config files, JSON, component props) and
are frequently handed to code that *does* bridge to JavaScript.  We
therefore reject the dangerous keys everywhere:

* :func:`is_dangerous_key` -- single key predicate.
* :func:`safe_merge` -- deep merge that never merges dangerous keys.
* :func:`sanitize_object` -- recursive cleanup of an existing object.
* :func:`get_path` -- path lookup restricted to *own* properties.
* :func:`has_pollution` -- recursive detector.
* :func:`safe_deepcopy` -- isolated deep copy of plain data.
* :func:`safe_delete` -- deletion restricted to own, safe properties.
* :func:`safe_to_dict` / :func:`safe_serialize` -- whitelisting
  serialisation which never emits dangerous keys.
* :func:`freeze_object` -- deeply immutable copy.
* :func:`sanitize_for_log` -- redacted, depth limited logging view.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import Any, Iterable, Optional

__all__ = [
    "DANGEROUS_KEYS",
    "is_dangerous_key",
    "sanitize_object",
    "safe_merge",
    "get_path",
    "has_pollution",
    "safe_deepcopy",
    "deep_copy",
    "safe_delete",
    "safe_delete_path",
    "safe_to_dict",
    "safe_serialize",
    "safe_dumps",
    "freeze_object",
    "FrozenDict",
    "sanitize_for_log",
    "redact_for_log",
]

#: Keys that may traverse or mutate the prototype chain in JavaScript.
DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})

_DANGEROUS_BYTES = frozenset(key.encode("ascii") for key in DANGEROUS_KEYS)

_MISSING = object()

# Values which are safe to return by reference (immutable scalars).
_SCALAR_TYPES = (str, bytes, int, float, bool, complex, type(None))

# Fields that should never be written to an error log in the clear.
_SENSITIVE_KEY_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|auth(?:orization)?|"
    r"cookie|session|credential|private[-_]?key|access[-_]?key|client[-_]?secret)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------
def is_dangerous_key(key: Any) -> bool:
    """Return ``True`` when *key* can be abused to pollute a prototype.

    The check is deliberately exact (JavaScript property names are case
    sensitive) and covers ``constructor`` / ``prototype`` in addition to
    ``__proto__``, since ``constructor.prototype`` is the classic bypass
    around a filter that only looks for ``__proto__``.  ``bytes`` keys
    are matched as well so a decoded-bytes key cannot slip through.
    """

    if isinstance(key, str):
        return key in DANGEROUS_KEYS
    if isinstance(key, bytes):
        return key in _DANGEROUS_BYTES
    return False


# ---------------------------------------------------------------------------
# Recursive sanitising / merging
# ---------------------------------------------------------------------------
def _sanitize(value: Any, memo: dict[int, Any]) -> Any:
    """Recursively rebuild *value* without dangerous keys.

    Containers become fresh plain ``dict`` / ``list`` / ``tuple``
    instances so no reference to an attacker-controlled object (and no
    inherited attribute) leaks into the result.  ``memo`` keeps shared
    references and cycles intact without recursing forever.
    """

    if isinstance(value, Mapping):
        existing = memo.get(id(value), _MISSING)
        if existing is not _MISSING:
            return existing
        out: dict[Any, Any] = {}
        memo[id(value)] = out
        for key, item in value.items():
            if is_dangerous_key(key):
                continue
            out[key] = _sanitize(item, memo)
        return out

    if isinstance(value, (list, tuple)):
        existing = memo.get(id(value), _MISSING)
        if existing is not _MISSING:
            return existing
        out_list: list[Any] = []
        memo[id(value)] = out_list
        for item in value:
            out_list.append(_sanitize(item, memo))
        if isinstance(value, tuple):
            result = tuple(out_list)
            memo[id(value)] = result
            return result
        return out_list

    if isinstance(value, (set, frozenset)):
        # Contents of a set are hashable, therefore never containers;
        # rebuilding is enough to detach them from the original set.
        return type(value)(_sanitize(item, memo) for item in value)

    # Arbitrary instances are reduced to their own attributes (as a
    # plain dict) rather than copied through ``copy.deepcopy``, which
    # would invoke attacker-supplied ``__deepcopy__`` / ``__reduce__``
    # hooks.  Scalars and objects without an instance dict are returned
    # as-is.
    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return _sanitize(own, memo)

    return value


def sanitize_object(value: Any) -> Any:
    """Return a recursively cleaned copy of *value*.

    All dangerous keys are removed at every nesting level.  Mappings
    become plain dictionaries, sequences are rebuilt element by element
    and class instances are reduced to their own (non-dangerous)
    attributes.  The original object is never mutated.
    """

    if isinstance(value, Mapping):
        return _sanitize(value, {})
    if isinstance(value, (list, tuple)):
        return _sanitize(value, {})
    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return {
            key: _sanitize(item, {})
            for key, item in own.items()
            if not is_dangerous_key(key)
        }
    return _sanitize(value, {})


def _merge_into(target: dict[Any, Any], source: Mapping) -> dict[Any, Any]:
    """Deep-merge *source* into *target*, skipping dangerous keys."""

    for key, value in source.items():
        if is_dangerous_key(key):
            continue
        current = target.get(key, _MISSING)
        # A frozen value cannot be merged in place; replace it with a
        # fresh mutable copy before recursing.
        if isinstance(current, FrozenDict):
            current = dict(current)
            target[key] = current
        if isinstance(current, dict) and isinstance(value, Mapping):
            _merge_into(current, value)
        else:
            target[key] = _sanitize(value, {})
    return target


def safe_merge(*args: Any, **kwargs: Any) -> dict[Any, Any]:
    """Deep merge untrusted objects without allowing prototype pollution.

    Later sources override earlier ones.  Nested mappings are merged
    recursively, while arrays and scalars replace the previous value
    (merging array indices is exactly what lets a polluted index
    survive).  Dangerous keys are dropped at every level, and the
    result is built from fresh containers so inputs are not mutated.

    Keyword arguments are treated as the final source, which keeps
    ``safe_merge(base, override, **extra)`` behaving as expected.
    """

    result: dict[Any, Any] = {}
    sources: list[Any] = list(args)
    if kwargs:
        sources.append(kwargs)

    for source in sources:
        if source is None:
            continue
        if isinstance(source, Mapping):
            _merge_into(result, source)
            continue
        own = getattr(source, "__dict__", None)
        if isinstance(own, dict):
            _merge_into(result, own)
            continue
        raise TypeError(
            f"safe_merge() expected a mapping, got {type(source).__name__}"
        )

    return result


# ---------------------------------------------------------------------------
# Path lookup
# ---------------------------------------------------------------------------
def _normalize_path(path: Any) -> Optional[list[Any]]:
    if isinstance(path, str):
        if not path:
            return None
        return path.split(".")
    if isinstance(path, (list, tuple)):
        return list(path) if path else None
    return None


def _coerce_index(part: Any) -> Optional[int]:
    if isinstance(part, bool):
        return None
    if isinstance(part, int):
        return part if part >= 0 else None
    if isinstance(part, str) and part.isdigit():
        return int(part)
    return None


def get_path(obj: Any, path: Any, default: Any = None) -> Any:
    """Read a dotted path, touching only own properties.

    ``path`` may be a string (``"a.b.0"``) or a sequence of segments.
    Inherited attributes, class attributes and prototype-walking
    segments are never followed: a dangerous segment or a missing own
    property yields *default*.
    """

    parts = _normalize_path(path)
    if parts is None:
        return default

    current = obj
    for part in parts:
        if isinstance(part, str) and is_dangerous_key(part):
            return default

        if isinstance(current, Mapping):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, (list, tuple)):
            index = _coerce_index(part)
            if index is None or index >= len(current):
                return default
            current = current[index]
        else:
            # Only inspect the instance dictionary -- ``getattr`` would
            # also resolve attributes provided by the class/prototype.
            own = getattr(current, "__dict__", None)
            if not isinstance(own, dict) or part not in own:
                return default
            current = own[part]

    return current


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def has_pollution(value: Any, _seen: Optional[set[int]] = None) -> bool:
    """Return ``True`` if any dangerous key exists anywhere in *value*."""

    if _seen is None:
        _seen = set()

    if isinstance(value, Mapping):
        if id(value) in _seen:
            return False
        _seen.add(id(value))
        for key, item in value.items():
            if is_dangerous_key(key):
                return True
            if has_pollution(item, _seen):
                return True
        return False

    if isinstance(value, (list, tuple, set, frozenset)):
        if id(value) in _seen:
            return False
        _seen.add(id(value))
        return any(has_pollution(item, _seen) for item in value)

    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return has_pollution(own, _seen)

    return False


# ---------------------------------------------------------------------------
# Isolated deep copy
# ---------------------------------------------------------------------------
def safe_deepcopy(value: Any, _memo: Optional[dict[int, Any]] = None) -> Any:
    """Deep-copy plain data, dropping dangerous keys.

    Unlike :func:`copy.deepcopy` this does not invoke ``__deepcopy__``,
    ``__reduce__`` or ``__getstate__`` hooks, so an attacker cannot run
    code during copying.  Instances with an instance ``__dict__`` are
    cloned through ``object.__new__`` and only their own enumerable
    fields are copied.
    """

    if _memo is None:
        _memo = {}

    if isinstance(value, _SCALAR_TYPES):
        return value

    existing = _memo.get(id(value), _MISSING)
    if existing is not _MISSING:
        return existing

    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        _memo[id(value)] = out
        for key, item in value.items():
            if is_dangerous_key(key):
                continue
            out[key] = safe_deepcopy(item, _memo)
        return out

    if isinstance(value, (list, tuple)):
        out_list: list[Any] = []
        _memo[id(value)] = out_list
        for item in value:
            out_list.append(safe_deepcopy(item, _memo))
        if isinstance(value, tuple):
            result = tuple(out_list)
            _memo[id(value)] = result
            return result
        return out_list

    if isinstance(value, (set, frozenset)):
        out_set = type(value)(safe_deepcopy(item, _memo) for item in value)
        _memo[id(value)] = out_set
        return out_set

    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        try:
            clone = object.__new__(type(value))
        except TypeError:
            clone = None
        if clone is not None:
            _memo[id(value)] = clone
            for key, item in own.items():
                if is_dangerous_key(key):
                    continue
                object.__setattr__(clone, key, safe_deepcopy(item, _memo))
            return clone
        # Cannot allocate a bare instance: fall back to safe plain data.
        return {
            key: safe_deepcopy(item, _memo)
            for key, item in own.items()
            if not is_dangerous_key(key)
        }

    return value


#: Convenience alias.
deep_copy = safe_deepcopy


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------
def safe_delete(target: Any, key: Any) -> bool:
    """Delete *key* from *target* only when it is own and safe.

    Returns ``True`` when something was removed.  Dangerous keys are
    always refused, even when they happen to be own keys, and inherited
    attributes can never be removed through this helper.
    """

    if is_dangerous_key(key):
        return False

    if isinstance(target, MutableMapping):
        if key in target:
            del target[key]
            return True
        return False

    if isinstance(target, MutableSequence):
        index = _coerce_index(key)
        if index is None or index >= len(target):
            return False
        del target[index]
        return True

    own = getattr(target, "__dict__", None)
    if isinstance(own, dict) and key in own:
        delattr(target, key)
        return True

    return False


def safe_delete_path(target: Any, path: Any) -> bool:
    """Delete the leaf of a dotted path, refusing dangerous segments."""

    parts = _normalize_path(path)
    if parts is None:
        return False
    parent = target if len(parts) == 1 else get_path(target, parts[:-1])
    if parent is None:
        return False
    return safe_delete(parent, parts[-1])


# ---------------------------------------------------------------------------
# Whitelisted serialisation
# ---------------------------------------------------------------------------
def safe_to_dict(value: Any, allowed_keys: Optional[Iterable[Any]] = None) -> Any:
    """Convert *value* to plain JSON-safe data without dangerous keys.

    When *allowed_keys* is given it acts as a whitelist applied to every
    mapping at every level.  Instances are reduced to their own
    attributes, cycles become the string ``"[Circular]"`` and unknown
    objects are rendered as their type name rather than dumped whole.
    """

    allowed = None if allowed_keys is None else {str(key) for key in allowed_keys}
    return _serialize_safe(value, allowed, set())


def _serialize_safe(value: Any, allowed: Optional[set[str]], seen: set[int]) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, Mapping):
        if id(value) in seen:
            return "[Circular]"
        seen.add(id(value))
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if is_dangerous_key(key):
                continue
            if allowed is not None and str(key) not in allowed:
                continue
            if not isinstance(key, (str, int, float, bool, type(None))):
                key = str(key)
            out[key] = _serialize_safe(item, allowed, seen)
        seen.discard(id(value))
        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        if id(value) in seen:
            return "[Circular]"
        seen.add(id(value))
        out_list = [_serialize_safe(item, allowed, seen) for item in value]
        seen.discard(id(value))
        return out_list

    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return _serialize_safe(own, allowed, seen)

    return f"<{type(value).__name__}>"


def safe_serialize(
    value: Any,
    allowed_keys: Optional[Iterable[Any]] = None,
    **json_kwargs: Any,
) -> str:
    """Serialise *value* as JSON using the whitelist from :func:`safe_to_dict`."""

    return json.dumps(safe_to_dict(value, allowed_keys), **json_kwargs)


#: Convenience alias.
safe_dumps = safe_serialize


# ---------------------------------------------------------------------------
# Freezing
# ---------------------------------------------------------------------------
class FrozenDict(dict):
    """A deeply-freezable dictionary that rejects every mutation."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("FrozenDict is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __copy__(self) -> "FrozenDict":
        return self


def freeze_object(value: Any, _memo: Optional[dict[int, Any]] = None) -> Any:
    """Return a deeply immutable copy of *value*.

    Mappings become :class:`FrozenDict`, sequences become tuples and
    sets become frozensets, so any later attempt to assign an item or
    append to a nested container raises ``TypeError``.  Dangerous keys
    are dropped while copying.
    """

    if _memo is None:
        _memo = {}

    if isinstance(value, _SCALAR_TYPES):
        return value

    existing = _memo.get(id(value), _MISSING)
    if existing is not _MISSING:
        return existing

    if isinstance(value, Mapping):
        out = FrozenDict()
        _memo[id(value)] = out
        for key, item in value.items():
            if is_dangerous_key(key):
                continue
            dict.__setitem__(out, key, freeze_object(item, _memo))
        return out

    if isinstance(value, (list, tuple)):
        out_list = [freeze_object(item, _memo) for item in value]
        result = tuple(out_list)
        _memo[id(value)] = result
        return result

    if isinstance(value, (set, frozenset)):
        out_set = frozenset(freeze_object(item, _memo) for item in value)
        _memo[id(value)] = out_set
        return out_set

    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return freeze_object(own, _memo)

    return value


# ---------------------------------------------------------------------------
# Log redaction
# ---------------------------------------------------------------------------
def sanitize_for_log(
    value: Any,
    max_depth: int = 6,
    max_items: int = 50,
    max_length: int = 256,
    redacted: str = "***",
) -> Any:
    """Build a safe, bounded view of *value* for error logging.

    Dangerous keys are removed, sensitive fields (passwords, tokens,
    cookies, ...) are masked, long strings are truncated, container
    sizes and recursion depth are capped and unknown objects are
    reduced to ``<TypeName>``.  The original object is never touched.
    """

    return _log_safe(
        value,
        depth=0,
        seen=set(),
        max_depth=max_depth,
        max_items=max_items,
        max_length=max_length,
        redacted=redacted,
    )


def _log_safe(
    value: Any,
    depth: int,
    seen: set[int],
    max_depth: int,
    max_items: int,
    max_length: int,
    redacted: str,
) -> Any:
    if isinstance(value, str):
        if len(value) > max_length:
            return value[:max_length] + "..."
        return value
    if isinstance(value, bytes):
        return _log_safe(
            value.decode("utf-8", errors="replace"),
            depth,
            seen,
            max_depth,
            max_items,
            max_length,
            redacted,
        )
    if isinstance(value, (int, float, bool, complex)) or value is None:
        return value

    if depth >= max_depth:
        return "[MaxDepth]"

    if isinstance(value, Mapping):
        if id(value) in seen:
            return "[Circular]"
        seen.add(id(value))
        out: dict[Any, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if is_dangerous_key(key):
                continue
            if index >= max_items:
                out["..."] = f"[{len(value) - max_items} more]"
                break
            if isinstance(key, str) and _SENSITIVE_KEY_RE.search(key):
                out[key] = redacted
                continue
            out[key] = _log_safe(
                item, depth + 1, seen, max_depth, max_items, max_length, redacted
            )
        seen.discard(id(value))
        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        if id(value) in seen:
            return "[Circular]"
        seen.add(id(value))
        items = list(value)
        out_list = [
            _log_safe(item, depth + 1, seen, max_depth, max_items, max_length, redacted)
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            out_list.append(f"[{len(items) - max_items} more]")
        seen.discard(id(value))
        return out_list

    own = getattr(value, "__dict__", None)
    if isinstance(own, dict):
        return _log_safe(
            own, depth, seen, max_depth, max_items, max_length, redacted
        )

    # Never render an arbitrary object's repr (`<Foo object at 0x...>`
    # can itself trigger attacker code); the type name is enough.
    return f"<{type(value).__name__}>"


#: Convenience alias.
redact_for_log = sanitize_for_log
