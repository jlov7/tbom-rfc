import json

from tbomctl import (
    compute_tool_digest,
    definition_digest_covers,
    jcs_canonicalize,
    tool_digest_input,
)

try:
    from hypothesis import given
    from hypothesis import strategies as st

    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False


def test_jcs_canonicalize():
    # RFC 8785 examples
    # Empty object
    assert jcs_canonicalize({}) == "{}"
    # Ordering
    assert jcs_canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    # Whitespace
    assert jcs_canonicalize({"a": 2}) == '{"a":2}'


def test_tool_digest_input():
    tool = {"name": "foo", "description": "bar", "inputSchema": {}, "extraField": "ignored"}
    digest_input = tool_digest_input(tool)
    assert "extraField" not in digest_input
    assert digest_input["name"] == "foo"
    assert digest_input["description"] == "bar"
    assert digest_input["inputSchema"] == {}

    # Optional fields
    tool_with_output = tool.copy()
    tool_with_output["outputSchema"] = {"type": "string"}
    digest_input_out = tool_digest_input(tool_with_output)
    assert "outputSchema" in digest_input_out


def test_compute_tool_digest():
    tool = {
        "name": "create_note",
        "description": "Create a new note in the user's vault.",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string"}, "body": {"type": "string"}},
            "required": ["title", "body"],
        },
    }
    _, digest = compute_tool_digest(tool)

    # Expected values from the whitepaper example (re-verified)
    # The digest value in the whitepaper for this tool is:
    # sha256:c8b0dd1582c61e53295ac07bae66448e67097a3b853ad6f2401025998b82dac7
    expected_digest = "sha256:c8b0dd1582c61e53295ac07bae66448e67097a3b853ad6f2401025998b82dac7"

    assert digest == expected_digest
    assert definition_digest_covers(tool) == "{name,description,inputSchema}"


def test_digest_covers_with_output_schema():
    tool = {"name": "foo", "description": "bar", "inputSchema": {}, "outputSchema": {}}
    assert definition_digest_covers(tool) == "{name,description,inputSchema,outputSchema}"


def test_digest_covers_with_annotations():
    tool = {"name": "foo", "description": "bar", "inputSchema": {}, "annotations": {"foo": "bar"}}
    assert definition_digest_covers(tool) == "{name,description,inputSchema,annotations}"


# Property-based tests using Hypothesis
if HYPOTHESIS_AVAILABLE:

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=50),
            st.one_of(
                st.text(),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False),
                st.booleans(),
                st.lists(st.one_of(st.text(), st.integers(), st.booleans()), max_size=5),
                st.dictionaries(st.text(min_size=1, max_size=10), st.text(), max_size=3),
            ),
            min_size=0,
            max_size=10,
        )
    )
    def test_jcs_canonicalize_deterministic(obj):
        """Test that JCS canonicalization is deterministic for any JSON object."""
        canonical1 = jcs_canonicalize(obj)
        canonical2 = jcs_canonicalize(obj)
        assert canonical1 == canonical2

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=50),
            st.one_of(
                st.text(),
                st.integers(),
                st.booleans(),
                st.lists(st.one_of(st.text(), st.integers(), st.booleans()), max_size=5),
                st.dictionaries(st.text(min_size=1, max_size=10), st.text(), max_size=3),
            ),
            min_size=0,
            max_size=10,
        )
    )
    def test_jcs_canonicalize_json_equivalence(obj):
        """Test that JCS canonicalization produces valid JSON that parses back to
        equivalent object (excluding floats due to canonicalization differences)."""
        canonical = jcs_canonicalize(obj)
        parsed = json.loads(canonical)
        # Note: JCS may canonicalize floats differently than Python's json.dumps
        # so we check that re-canonicalizing gives the same result
        re_canonicalized = jcs_canonicalize(parsed)
        assert re_canonicalized == canonical

    @given(
        st.text(min_size=1, max_size=100),
        st.text(min_size=1, max_size=500),
        st.dictionaries(
            st.text(min_size=1, max_size=50),
            st.one_of(st.text(), st.integers(), st.booleans()),
            min_size=0,
            max_size=10,
        ),
    )
    def test_tool_digest_deterministic(name, description, input_schema):
        """Test that tool digest computation is deterministic."""
        tool = {"name": name, "description": description, "inputSchema": input_schema}

        _, digest1 = compute_tool_digest(tool)
        _, digest2 = compute_tool_digest(tool)
        assert digest1 == digest2
        assert digest1.startswith("sha256:")

    @given(
        st.text(min_size=1, max_size=100),
        st.text(min_size=1, max_size=500),
        st.dictionaries(
            st.text(min_size=1, max_size=50),
            st.one_of(st.text(), st.integers(), st.booleans()),
            min_size=0,
            max_size=10,
        ),
        st.one_of(st.none(), st.dictionaries(st.text(min_size=1, max_size=20), st.text(), min_size=0, max_size=5)),
        st.one_of(st.none(), st.dictionaries(st.text(min_size=1, max_size=20), st.text(), min_size=0, max_size=5)),
    )
    def test_tool_digest_with_optional_fields(name, description, input_schema, output_schema, annotations):
        """Test tool digest computation with optional fields."""
        tool = {"name": name, "description": description, "inputSchema": input_schema}

        if output_schema is not None:
            tool["outputSchema"] = output_schema
        if annotations is not None:
            tool["annotations"] = annotations

        # Should not raise an exception
        canonical, digest = compute_tool_digest(tool)
        assert isinstance(canonical, str)
        assert isinstance(digest, str)
        assert digest.startswith("sha256:")

    @given(
        st.text(min_size=1, max_size=100),
        st.text(min_size=1, max_size=500),
        st.dictionaries(
            st.text(min_size=1, max_size=50),
            st.one_of(st.text(), st.integers(), st.booleans()),
            min_size=0,
            max_size=10,
        ),
    )
    def test_definition_digest_covers_fields(name, description, input_schema):
        """Test that definition_digest_covers correctly identifies included fields."""
        tool = {"name": name, "description": description, "inputSchema": input_schema}

        covers = definition_digest_covers(tool)
        assert "name" in covers
        assert "description" in covers
        assert "inputSchema" in covers

        # Test with optional fields
        tool_with_output = tool.copy()
        tool_with_output["outputSchema"] = {"type": "string"}
        covers_with_output = definition_digest_covers(tool_with_output)
        assert "outputSchema" in covers_with_output

        tool_with_annotations = tool.copy()
        tool_with_annotations["annotations"] = {"mcp": "tool"}
        covers_with_annotations = definition_digest_covers(tool_with_annotations)
        assert "annotations" in covers_with_annotations

    @given(st.text(min_size=1, max_size=100))
    def test_tool_digest_input_filtering(name):
        """Test that tool_digest_input properly filters out null values and extra fields."""
        tool = {
            "name": name,
            "description": "test description",
            "inputSchema": {"type": "object"},
            "extraField": "should be removed",
            "nullField": None,
            "nestedNull": {"inner": None},
        }

        filtered = tool_digest_input(tool)

        assert "extraField" not in filtered
        assert "nullField" not in filtered
        assert "nestedNull" not in filtered  # nested null objects are completely removed
