SAFE_BASE_PATTERNS = [
    "TEST_XSS_MARKER",
    "SAFE_SCRIPT_TOKEN(TEST_XSS)",
    "INJECT_TEST[EVENT_HANDLER]_XSS",
    "DOM_SINK_TEST::document.location::TEST_XSS",
    "ATTR_TEST_QUOTE_BREAK_TEST_XSS",
    "TAG_PATTERN_TEST_XSS_VECTOR",
    "FILTER_EVASION_TEST_XSS_CASE",
    "WAF_BYPASS_SIMULATION_TEST_XSS",
    "ENCODED_CONTEXT_TEST_XSS_PAYLOAD",
    "POLYGLOT_SAFE_MARKER_TEST_XSS",
]

PATTERN_CATEGORIES = {
    "marker": 1,
    "attribute_context": 2,
    "tag_context": 2,
    "dom_context": 3,
    "polyglot_like": 3,
}

CATEGORY_RULES = {
    "marker": ["TEST_XSS_MARKER", "WAF_BYPASS_SIMULATION"],
    "attribute_context": ["ATTR_TEST", "QUOTE_BREAK"],
    "tag_context": ["TAG_PATTERN", "SAFE_SCRIPT_TOKEN"],
    "dom_context": ["DOM_SINK_TEST", "document.location"],
    "polyglot_like": ["POLYGLOT", "EVENT_HANDLER"],
}
