from security.prototype_guard import (
    safe_merge,
    is_dangerous_key,
    sanitize_object,
    get_path,
    has_pollution
)


def test_merge():
    assert safe_merge({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}

def test_proto_key():
    assert is_dangerous_key('__proto__') is True

def test_constructor_key():
    assert is_dangerous_key('constructor') is True

def test_prototype_key():
    assert is_dangerous_key('prototype') is True

def test_safe_key():
    assert is_dangerous_key('name') is False

def test_merge_proto():
    assert safe_merge({'__proto__': {'x': 1}}, {}) == {}

def test_merge_nested():
    assert safe_merge({'a': {'__proto__': {'x': 1}}}, {}) == {'a': {}}

def test_sanitize():
    assert sanitize_object({'a': 1, '__proto__': {'x': 1}}) == {'a': 1}

def test_sanitize_nested():
    assert sanitize_object({'a': {'constructor': {'x': 1}, 'b': 2}}) == {'a': {'b': 2}}

def test_get_path():
    assert get_path({'a': {'b': 1}}, 'a.b') == 1

def test_get_proto():
    assert get_path({'a': 1}, '__proto__.x') is None

def test_pollution_true():
    assert has_pollution({'__proto__': {'polluted': True}}) is True

def test_pollution_false():
    assert has_pollution({'a': 1}) is False

def test_override():
    assert safe_merge({'a': [1]}, {'a': [2]}) == {'a': [2]}

def test_empty():
    assert safe_merge({}, {}) == {}
