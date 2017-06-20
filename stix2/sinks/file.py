import os

from stix2.sinks import DataSink


class FileDataSink(DataSink):
    """STIX 2.0 Data Sink - File module

        modes:
            must_not_exist - the file must not exist
            overwrite - if the file exists, overwrite it
            append - if the file exists, append any saved content
            replace - replace based on id
    """
    # class variables

    root_directory_path = None

    def __init__(self, file_path, mode="must_not_exist", absolute_path=False):

        self.mode = mode
        if FileDataSink.root_directory_path and not absolute_path:
            self.full_file_path = os.path.join(FileDataSink.root_directory_path, file_path)
        else:
            self.full_file_path = file_path

        super(FileDataSink, self).__init__(name=self.full_file_path)

        if not os.path.exists(self.full_file_path) and mode == "must_not_exist":
            self.file_handle = open(file_path, 'w')
        elif mode == "overwrite":
            self.file_handle = open(file_path, 'w')
        elif mode == "append":
            self.file_handle = open(file_path, 'a')
        elif mode == "replace":
            raise NotImplementedError()

    def close(self):
        self.file_handle.close()

    def save(self, obj):
        if self.mode != "replace":
            self.file_handle.write(str(obj) + "\n\n")

    @classmethod
    def set_root_directory_name(cls, path):
        cls.root_directory_path = path
