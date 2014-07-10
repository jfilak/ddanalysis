import os
import zlib
from ddanalysis.knowledgebase import DDAnalyzer, DDAnalyzerError, DDPredicate


class DDContentAnalyzer(DDAnalyzer):

    def __init__(self):
        super(DDContentAnalyzer, self).__init__()

    def initialize_markers(self, markers):
        markers["files"] = []

    def process(self, ddtar, markers):
        files = []
        try:
            for mmbr in ddtar.getmembers():
                if mmbr.name != os.path.basename(mmbr.name):
                    raise DDAnalyzerError("Outside of the directory '{0}'".format(mmbr.name))
                elif not mmbr.isfile():
                    raise DDAnalyzerError("Not a file '{0}'".format(mmbr.name))
                else:
                    files.append((mmbr.name, mmbr.size))
        except zlib.error as ex:
            raise DDAnalyzerError("{0}".format(str(ex)))
        except IOError as ex:
            raise DDAnalyzerError("{0}".format(str(ex)))

        markers["files"] = files

        return (True, None)


class DDFilePredicate(DDPredicate):

    def __init__(self, filename):
        super(DDFilePredicate, self).__init__()

        self._filename = filename

    def _satisfied_by_member(self, mmbr):
        raise NotImplementedError()

    def satisfied_by(self, markers):
        mmbr = None
        try:
            mmbr = next(x for x in markers["files"] if x[0] == self._filename)
        except StopIteration:
            # StopIteration is intented to be passed
            pass

        return self._satisfied_by_member(mmbr)


class DDMissingFilePredicate(DDFilePredicate):

    def __init__(self, filename):
        super(DDMissingFilePredicate, self).__init__(filename)

    def _satisfied_by_member(self, mmbr):
        if mmbr is None:
            return (True, ["Missing: " + self._filename])
        else:
            return (False, ["Exists: " + self._filename])

    @property
    def name(self):
        return "Missing '{0}'".format(self._filename)


class DDEmptyFilePredicate(DDFilePredicate):

    def __init__(self, filename):
        super(DDEmptyFilePredicate, self).__init__(filename)

    def _satisfied_by_member(self, mmbr):
        if mmbr is None:
            return (False, ["Unknow empty (missing): " + self._filename])
        else:
            if mmbr[1] == 0:
                return (True, ["Empty: " + self._filename])
            else:
                return (False, ["Size ({1}): {0}".format(mmbr[0], mmbr[1])])

    @property
    def name(self):
        return "Empty '{0}'".format(self._filename)

