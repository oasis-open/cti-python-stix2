from abc import abstractmethod


class DatabaseConnection():
    def __init__(self):
        pass

    @abstractmethod
    def execute(self, sql_statement, bindings):
        """

        Args:
            sql_statement: the statement to execute
            bindings: a dictionary where the keys are the column names and the values are the data to be
            inserted into that column of the table

        Returns:

        """
        pass

    @abstractmethod
    def create_insert_statement(self, table_name, bindings, **kwargs):
        """

        Args:
            table_name: the name of the table to be inserted into
            bindings: a dictionary where the keys are the column names and the values are the data to be
            inserted into that column of the table
            **kwargs: other specific arguments

        Returns:

        """
        pass
