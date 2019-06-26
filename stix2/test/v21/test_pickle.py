import pickle

import stix2

from .constants import IDENTITY_ID


def test_pickling():
    """
    Ensure a pickle/unpickle cycle works okay.
    """
    identity = stix2.v21.Identity(
        id=IDENTITY_ID,
        name="alice",
        description="this is a pickle test",
        identity_class="some_class",
    )

    pickle.loads(pickle.dumps(identity))
