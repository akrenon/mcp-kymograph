"""Running a corpus entry's server where its network attempts are observed and go nowhere.

``policy`` decides from an entry's provenance which isolation it may run under, before
anything starts. ``runner`` builds the runc sandbox, proves it with a positive probe and only
then lets the target be created; ``egress`` reads the kernel's record and holds the sink's
account against it; ``inside`` is what runs in the sandbox's own containers. Nothing is
imported here, so reading the policy does not pull in the machinery.
"""
