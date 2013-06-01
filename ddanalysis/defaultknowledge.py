# coding=UTF-8
import sys

from ddanalysis.knowledgebase import (DDKnowledgeBase)

from ddanalysis.contentanalysis import (DDContentAnalyzer,
                                        DDMissingFilePredicate,
                                        DDEmptyFilePredicate)

from ddanalysis.members.memberanalysis import (DDFilesAnalyzer,
                                               DDRegexTrait,
                                               DDTraitPredicate)

from ddanalysis.members.packageversion import (DDPackageVersionAnalyzer,
                                               DDVersionPredicate)

from ddanalysis.members.backtrace import (DDOopsCallTraceTrait,
                                          DDBacktraceFrameCountPredicate)


def load_knowledgebase():
    ddkb = DDKnowledgeBase()
    ddfa = DDFilesAnalyzer(sys.stdout)

    ddkb.analyzers.append(DDContentAnalyzer())
    ddkb.analyzers.append(ddfa)

    pcoredumped = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*\(core dumped\).*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*\(`core' generado\).*", sys.stdout)))))

    pccpp = DDTraitPredicate(ddfa.add_reader("analyzer", DDRegexTrait("^CCpp$", sys.stdout)))
    pkoops = DDTraitPredicate(ddfa.add_reader("analyzer", DDRegexTrait("^Kerneloops$", sys.stdout)))
    pxorg = DDTraitPredicate(ddfa.add_reader("analyzer", DDRegexTrait("^xorg$", sys.stdout)))
    ppython = DDTraitPredicate(ddfa.add_reader("analyzer", DDRegexTrait("^Python$", sys.stdout)))
    pvmcore = DDTraitPredicate(ddfa.add_reader("analyzer", DDRegexTrait("^vmcore$", sys.stdout)))

    ddfa.add_reader("backtrace", DDOopsCallTraceTrait(sys.stdout))

    pkoopszero = DDBacktraceFrameCountPredicate(0).and_this(pkoops)
    ddkb.add_problem(pkoopszero.and_this(pcoredumped), "A bug in btparser which was already fixed #903140")

    pkilled11 = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*killed by signal 11\).*", sys.stdout)))
    ddkb.add_problem(pkilled11.and_this(DDMissingFilePredicate("architecture")), "reporter-bugzilla dying due to missing 'architecture'")
    ddkb.add_problem(pcoredumped.or_this(pkilled11), "Something called by us is crashing!")

    # why are component pkg_* files empty?
    ddkb.add_problem(DDEmptyFilePredicate("component"), "Strange! Need more investigation.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*error validating.*RFRemix.*", sys.stdout)))
            , "Should be fixed on FAF server or even better should RFRemix should use actual libreport!")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Killed by garbage collector.*", sys.stdout)))
            , "Generating backtrace consumed too much time. We had to interrupt your task in order to let tasks from others user be processed. Please, generate the stacktrace locally.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*conflicts between attempted installs.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*WARNING:root:WARNING:root:No debuginfo found for.*", sys.stdout))))
            , "Broken debug infos or updated repository. Try to generate the backtrace later.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*but the retrace server only accepts crashes smaller.*", sys.stdout)))
            , "We are sorry but you have to generate the backtrace locally. Your coredump would consume too much of shared resources.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Retrace server is unable to process package.*", sys.stdout)))
            , "This package is probably not supported by retrace server. rpm -qi $PACKAGE")

    ddfa.add_reader("abrt_version", DDPackageVersionAnalyzer("abrt", sys.stdout))

    pusercancel = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Can't continue without.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Do you want to generate a stack trace locally.*'NO'$", sys.stdout)))))

    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(pusercancel)
            , "Cannot say more. Processing was interrupted on you request.")

    ddkb.add_problem(pusercancel, "D'oh! Exit status for user cancellation doesn't work!")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Either the product.*does not exist or you don't have access to it.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*There is no component named.*", sys.stdout))))
            , "Bad product or component sent to Bugzilla. This happen when you try to report to a wrong Bugzilla server. For example bugzilla.redhat.com accepts reports only from Fedora and Red Hat and packages provided by these OS")

    # Extend it to rawhide !!!
    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*There is no version named.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*The version value.*is not active", sys.stdout))))
            , "Version of your system is not supported on Bugzilla server.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("os_release", DDRegexTrait("^oVirt Node*", sys.stdout)))
            .and_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*error validating 'version'.*", sys.stdout))))
            , "You are reporting from an unsupported distribution")

    pdupid = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*CLOSED.*DUPLICATE.*DUP_ID.*", sys.stdout)))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*LEZÁRVA.*DUPLIKÁLT.*DUP_ID.*", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*CERRADO.*DUPLICADO.*DUP_ID.*", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*UZAVŘENA.*DUPLIKÁT.*DUP_ID.*", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*ДУБЛИКАТ.*DUP_ID.*", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*但它没有.*DUP_ID.*", sys.stdout)))))

    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(pdupid)
        , "Problem with XML RPC changes in reporter-bugzilla which has been already fixed.")

    ddkb.add_problem(pdupid, "Reading bad field from XMP RPC response in reporter-bugzilla.")

    pshutdown = DDMissingFilePredicate("count").and_this(
            pccpp.or_this(pkoops).or_this(pxorg).or_this(ppython).or_this(pvmcore))

    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(pshutdown)
        , "Problem has been detected while shut down and ABRT cannot handle it.")

    ddkb.add_problem(DDMissingFilePredicate("not-reportable").and_this(pshutdown)
        , "Oh Jesus! The this problem should be marked as not_reportable")

    ddkb.add_problem(pshutdown, "I wonder how someone could report this problem. It is NOT-REPOTABLE!")

    ddkb.add_problem(DDMissingFilePredicate("core_backtrace").and_this(pkoopszero)
            , "Cannot generate core backtrace from empty stacktrace")

    #ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.0",), DDVersionPredicate.LT)
    #                .or_this(DDVersionPredicate("abrt", ("2.1.0",), DDVersionPredicate.EQ)))

    gluuid = ddfa.add_reader("event_log", DDRegexTrait(".*'global_uuid'.*", sys.stdout))
    puuid = DDTraitPredicate(gluuid)

    ddkb.add_problem(pkoopszero.and_this(puuid),
            "Empty stacktrace cannot be hashed. Must see the original oops form /var/log/messages or dmesg.")

    anmi = ddfa.add_reader("backtrace", DDRegexTrait(".*<NMI>.*", sys.stdout))
    p = puuid.and_this(DDTraitPredicate(anmi)).and_this(pkoops.or_this(pvmcore))

    # old version, a user should update his package
    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(p)
            , "Unsupported NMI frames in oops stacktraces. An updated package has been released.")

    # outstanding because it was fixed in 2.1.4
    ddkb.add_problem(p, "Unsupported NMI frames in oops stacktraces. REGRESSION!")

    pred = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*missing mandatory element.*", sys.stdout)))
    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.0",), DDVersionPredicate.GT).and_this(pred)
            , "The problem was detected by too old abrt. If it is necessary to report it, please do so in the expert mode.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*error validating.*", sys.stdout)))
            , "Cannot say, open the dump directory and find what was wrong")

    pred = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*reporter-ureport: command not found.*", sys.stdout)))
    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(pred)
            , "Missing dependency on libreport-plugin-ureport but an update package has been released")
    ddkb.add_problem(pred, "Missing dependency on libreport-plugin-ureport. REGRESSION!")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*This problem does not have an uReport assigned.*", sys.stdout)))
            , "Reporting to bugzilla a problem which was rejected by FAF.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*fatal: HTTP response code is 50., not 200.*", sys.stdout)))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Proxy CONNECT aborted.*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*RPC failed at server.*at .* line .*", sys.stdout))))
            , "Problem with bugzilla proxy. Please, try to report your problem later.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*has been locked out of this account until.*", sys.stdout)))
            , "Blocked bugzilla account. Please, wait or contact bugzilla admistrators.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*XML-RPC response too large.*", sys.stdout)))
            , "Bug in reporter-bugzilla. Response must be increased.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Could not resolve host.*", sys.stdout)))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*couldn't connect to host*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*NSS error.*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Connection timed out.*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*I/O operation timed out.*", sys.stdout))))
            , "Network connection problem.")

    return ddkb
