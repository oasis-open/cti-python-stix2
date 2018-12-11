import pickle

import stix2


def test_pickling():
    """
    Ensure a pickle/unpickle cycle works okay.
    """
    identity = stix2.v21.Identity(
        id="identity--d66cb89d-5228-4983-958c-fa84ef75c88c",
        name="alice",
        description="this is a pickle test",
        identity_class="some_class",
    )

    pickle.loads(pickle.dumps(identity))
