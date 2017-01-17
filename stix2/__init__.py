import uuid


class Indicator:

    def __init__(self):
        self.id = "indicator--" + str(uuid.uuid4())
