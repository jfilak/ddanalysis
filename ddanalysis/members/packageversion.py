from distutils import version
from ddanalysis.knowledgebase import DDPredicate
from ddanalysis.members.memberanalysis import DDTrait


class DDPackageVersionAnalyzer(DDTrait):

    def __init__(self, name, logfile):
        super(DDPackageVersionAnalyzer, self).__init__("Version of " + name, logfile)
        self._name = name
        self._logfile = logfile

    def nextline(self, line, markers):
        if line is None:
            return

        if self._name in markers["versions"]:
            raise RuntimeError, " version alredy there"

        markers["versions"][self._name] = (line, None, None)


class DDVersionPredicate(DDPredicate):
    LT = 0
    EQ = 1
    GT = 2

    def __init__(self, name, verel, eqtype):
        super(DDVersionPredicate, self).__init__()

        self._name = name

        self._version = version.StrictVersion(verel[0])
        self._nvr = verel[0]

        if len(verel) > 1:
            self._release = verel[1]
            self._nvr += "-"
            self._nvr += str(self._release)
        else:
            self._release = None

        self._eq = eqtype
        self._sd = "{0} {1} {2}".format(name,
                ["<", "==", ">"][self._eq], self._nvr)


    def satisfied_by(self, markers):
        if not self._name in markers["versions"]:
            return (False, ["No version of " + self._name])

        vobj = version.StrictVersion(markers["versions"][self._name][0])

        if self._version > vobj:
            res = self._eq == DDVersionPredicate.LT
        elif self._version < vobj:
            res = self._eq == DDVersionPredicate.GT
        else:
            res = self._eq == DDVersionPredicate.EQ

        return (res, [self._sd])

    @property
    def name(self):
        return self._sd

