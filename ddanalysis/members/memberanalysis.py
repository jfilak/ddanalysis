import re
from collections import defaultdict
from ddanalysis.knowledgebase import DDAnalyzer, DDPredicate


class DDFilesAnalyzer(DDAnalyzer):

    def __init__(self, logfile):
        super(DDFilesAnalyzer, self).__init__()

        self._analyzers = defaultdict(list)
        self._logfile = logfile

    def add_reader(self, fname, analyzer):
        self._analyzers[fname].append(analyzer)
        return analyzer

    def initialize_markers(self, markers):
        markers["traits"] = list()
        markers["versions"] = dict()
        markers["backtrace"] = dict()

    def process(self, ddtar, markers):
        for name, readers in self._analyzers.items():
            try:
                next((x for x in markers["files"] if x[0] == name))
            except StopIteration as ex:
                self._logfile.write("Skip missing trait analyzer because of missing: '{0}'\n".format(name))
                continue

            fmmbr = None
            try:
                fmmbr = ddtar.extractfile(name)
                for filine in fmmbr.readlines():
                    for reader in readers:
                        reader.nextline(filine, markers)
                for reader in readers:
                    reader.nextline(None, markers)
            except IOError as ex:
                self._logfile.write("{0}\n".format(str(ex)))
                continue
            finally:
                # with ddtar.extractfile(info) as fmmbr:
                # AttributeError: __exit__
                if fmmbr is not None:
                    fmmbr.close()

        return (True, "Success")


class DDTrait(object):

    def __init__(self, idname, logfile):
        self._idname = idname
        self._logfile = logfile

    def nextline(self, line, markers):
        raise NotImplementedError()

    @property
    def identifier(self):
        return self._idname


class DDRegexTrait(DDTrait):

    def __init__(self, regexp, logfile):
        super(DDRegexTrait, self).__init__(regexp, logfile)
        self._regexp = re.compile(regexp)

    def nextline(self, line, markers):
        if line is not None and self._regexp.match(line):
            markers["traits"].append((self.identifier, line.rstrip('\n')))


class DDTraitPredicate(DDPredicate):

    def __init__(self, analyzer):
        super(DDTraitPredicate, self).__init__()

        self._analyzer = analyzer

    def satisfied_by(self, markers):
        result = False
        log = list()
        for trait in markers["traits"]:
            if trait[0] == self._analyzer.identifier:
                result = True
                log.append(trait[1])

        return (result, log)

    @property
    def name(self):
        return self._analyzer.identifier


