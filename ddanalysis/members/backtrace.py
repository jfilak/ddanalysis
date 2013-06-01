import re
from ddanalysis.knowledgebase import DDPredicate
from ddanalysis.members.memberanalysis import DDTrait


class DDOopsCallTraceTrait(DDTrait):

    def __init__(self, logfile):
        super(DDOopsCallTraceTrait, self).__init__("Koops Stack Trace", logfile)
        self._calltrace = re.compile("^Call Trace:.*")
        self._frame = re.compile(r".*\[<.*>\] .*\+0x.*/0x.*")
        self._stack = False

    def nextline(self, line, markers):
        if line is not None and self._calltrace.match(line):
            self._stack = True
            return

        if self._stack:
            if line is not None and self._frame.match(line):
                btinfo = markers['backtrace']
                count = btinfo.get('framescount', 0)
                btinfo['framescount'] = count + 1
            else:
                self._stack = False


class DDBacktraceFrameCountPredicate(DDPredicate):

    def __init__(self, number):
        super(DDBacktraceFrameCountPredicate, self).__init__()

        self._number = number
        self._identifier = "Frames number is {0}".format(number)

    def satisfied_by(self, markers):
        readnumber = markers["backtrace"].get('framescount', 0)
        if readnumber == self._number:
            return (True, ["Frame matches the number"])

        return (False, ["Frames number doesn't match"])

    @property
    def name(self):
        return self._identifier

