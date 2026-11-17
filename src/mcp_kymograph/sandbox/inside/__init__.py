"""What runs inside the sandbox's own containers: the sink, the helper, the reader, the probe.

Standard library only, and importable both ways: as this package on the host (tests, and the
host reading the same constants) and as plain scripts inside the containers, where this
directory is mounted read-only and each script finds its siblings next to itself.
"""
