from abc import abstractmethod


class DatabaseConnection():

    def __init__(self):
        pass

    @abstractmethod
    def execute(self, sql_statement, bindings):
        """

        Args:
            bindings:

        Returns:

        """
