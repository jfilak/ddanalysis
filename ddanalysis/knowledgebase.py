import tarfile

class DDPredicate(object):

    def __init__(self):
        pass

    def satisfied_by(self, markers):
        raise NotImplementedError()

    def and_this(self, other):
        return DDPredicateAND(self, other)

    def or_this(self, other):
        return DDPredicateOR(self, other)

    def not_(self):
        return DDPredicateNOT(self)


class DDPredicateAND(DDPredicate):

    def __init__(self, lhs, rhs):
        super(DDPredicateAND, self).__init__()

        self._lhs = lhs
        self._rhs = rhs

    @property
    def name(self):
        return "{0} && {1}".format(self._lhs.name, self._rhs.name)

    def satisfied_by(self, markers):
        res, log = self._lhs.satisfied_by(markers)
        if res:
            res, rhs_log = self._rhs.satisfied_by(markers)
            log = log + rhs_log

        return (res, log)


class DDPredicateOR(DDPredicate):

    def __init__(self, lhs, rhs):
        super(DDPredicateOR, self).__init__()

        self._lhs = lhs
        self._rhs = rhs

    @property
    def name(self):
        return "{0} || {1}".format(self._lhs.name, self._rhs.name)

    def satisfied_by(self, markers):
        res, log = self._lhs.satisfied_by(markers)
        if not res:
            res, log = self._rhs.satisfied_by(markers)

        return (res, log)


class DDPredicateNOT(DDPredicate):

    def __init__(self, lhs):
        super(DDPredicateNOT, self).__init__()

        self._lhs = lhs

    @property
    def name(self):
        return "NOT {0}".format(self._lhs.name)

    def satisfied_by(self, markers):
        res, log = self._lhs.satisfied_by(markers)
        res = not res

        return (res, log)


class DDAnalyzerError(Exception):

    def __init__(self, message):
        super(DDAnalyzerError, self).__init__(message)


class DDAnalyzer(object):

    def __init__(self):
        pass

    def initialize_markers(self, markers):
        raise NotImplementedError()

    def process(self, ddtar, markers):
        raise NotImplementedError()

class DDKnowledgeBase(object):

    def __init__(self):
        self._analyzers = list()
        self._problems = list()

    @property
    def analyzers(self):
        return self._analyzers

    def add_problem(self, predicate, message):
        return self._problems.append((predicate, message))

    def proceed_dump_dir(self, ddname, markers):
        for analyzer in self._analyzers:
            analyzer.initialize_markers(markers)

        with tarfile.open(ddname, "r:gz") as ddtar:
            for analyzer in self._analyzers:
                analyzer.process(ddtar, markers)

        for (prblm, message) in self._problems:
            sat, log = prblm.satisfied_by(markers)
            if sat:
                return (prblm.name, message, log)

        return None

