class UnsupportedSigma(ValueError):
    """A rule uses a Sigma feature this converter does not translate. The rule is skipped
    with this reason rather than emitting SPL that would silently behave differently."""
