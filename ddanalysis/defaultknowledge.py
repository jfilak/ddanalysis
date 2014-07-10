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

    ddkb.add_problem(pkoops.or_this(pvmcore).and_this(DDMissingFilePredicate("pkg_epoch")),
            "Failed to get kernel info -> post-create failed")
    ddkb.add_problem((pccpp.or_this(pxorg).or_this(ppython)).and_this(DDMissingFilePredicate("executable").or_this(DDMissingFilePredicate("os_release")))
            .or_this(pccpp.and_this(DDMissingFilePredicate("coredump"))),
            "Corrupted problem data because of tmpfiles clean-up!")

    pkilled11 = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*killed by signal 11\).*", sys.stdout)))
    ddkb.add_problem(pkilled11.and_this(DDMissingFilePredicate("architecture")), "reporter-bugzilla dying due to missing 'architecture'")
    ddkb.add_problem(pcoredumped.or_this(pkilled11), "Something called by us is crashing!")

    # why are component pkg_* files empty?
    ddkb.add_problem(DDEmptyFilePredicate("component"), "Strange! Need more investigation.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*error validating.*RFRemix.*", sys.stdout)))
            , "Should be fixed on FAF server or even better should RFRemix should use actual libreport!")

    # Element 'os' is invalid: Element 'name' is invalid
    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("os_info", DDRegexTrait("ID=fedora", sys.stdout))).not_().and_this(DDTraitPredicate(ddfa.add_reader("os_info", DDRegexTrait("ID=*.", sys.stdout)))),
            "Unsupported OS")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Killed by garbage collector.*", sys.stdout)))
            , "Generating backtrace consumed too much time. We had to interrupt your task in order to let tasks from others user be processed. Please, generate the stacktrace locally.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*conflicts between attempted installs.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*WARNING:root:WARNING:root:No debuginfo found for.*", sys.stdout))))
            , "Broken debug infos or updated repository. Try to generate the backtrace later.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Retrace failed. Try again later and if the problem persists report this issue please..*", sys.stdout)))
            , "Retrace server has problem with chroot initialization.")

    ptoobig = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*but the retrace server only accepts (crashes|archives) smaller.*", sys.stdout))).or_this(
                DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Размер архива составляет \d+ байт, но отслеживающий сервер принимает не больше \d+ байт.*", sys.stdout)))).or_this(
                DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*La taille de l'archive est de \d+ octets, mais le serveur retrace accepte uniquement des archives de taille inférieure ou égale à \d+ octets.*", sys.stdout))))

    ddkb.add_problem(ptoobig, "We are sorry but you have to generate the backtrace locally. Your coredump would consume too much of shared resources.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Retrace server is unable to process package.*", sys.stdout))).or_this(
                     DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*El servidor Retrace no puede procesar el paquete.*", sys.stdout)))).or_this(
                     DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Сервер перетрассировки не может обработать пакет.*", sys.stdout))))
            , "This package is probably not supported by retrace server. rpm -qi $PACKAGE")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*The release '.*' is not supported by the Retrace server.*", sys.stdout))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*La révision.*n'est pas prise en charge par le serveur Retrace.*", sys.stdout))))
            , "Retrace coredump for EOLed release.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Error: Line \d+, column \d+: \"Thread\" header expected.*", sys.stdout)))
            , "Broken backtrace caused by backtrace shortening. Disabled 'thread apply all'.")

    pimportreport = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*import report.*", sys.stdout)))

    paaie = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*/usr/bin/abrt-action-perform-ccpp-analysis\", line \d+, in.*", sys.stdout))).and_this(pimportreport)
    ddkb.add_problem(paaie, "Missing dependency libreport-plugin in abrt-addon-ccpp")

    pmodule = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*No module named.*", sys.stdout)))

    ddkb.add_problem(pmodule.and_this(paaie.not_()), "Broken package dependencies.")

    ddkb.add_problem(pkoops.and_this(DDTraitPredicate(ddfa.add_reader("backtrace", DDRegexTrait(".*EOI.*", sys.stdout))))
                           .and_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Validation failed.*18446744073709551615.*", sys.stdout)))),
                     "Bug in satyr https://github.com/abrt/satyr/issues/108")

    ddfa.add_reader("abrt_version", DDPackageVersionAnalyzer("abrt", sys.stdout))
    ddfa.add_reader("satyr_version", DDPackageVersionAnalyzer("satyr", sys.stdout))

    pnofilename = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*Element 'file_name' is missing", sys.stdout)))
    pccppfilename = pccpp.and_this(pnofilename)

    ddkb.add_problem(pccppfilename.and_this(DDVersionPredicate("satyr", ("0.13",), DDVersionPredicate.GT)), "Unwinding cannot get file_name with satyr > 0.13")

    ddkb.add_problem(pccppfilename.and_this(DDVersionPredicate("satyr", ("0.14",), DDVersionPredicate.LT)), "Fixed CCpp file_name")

    ddkb.add_problem(pkoops.and_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(r".*Element 'function_name' is missing.*", sys.stdout)))), "Kooops misses function_name")

    # Need extension -> multi-line log
    pretraceservererror = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*A server-side error occurred on '.*'.*", sys.stdout)))
            .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Um erro ocorreu enquanto se conectava a '.*'.*", sys.stdout)))))
    ddkb.add_problem(pretraceservererror, "Retrace server experienced an internal error!")

    prsyes = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Ok to upload core dump?.*YES.*", sys.stdout)))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Sind Sie damit einverstanden, den Speicherauszug hochzuladen?.*YES.*", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Отправить дамп ядра?.*YES.*", sys.stdout)))))

    pgdbcancel = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Do you want to generate a stack trace locally.*'NO'$", sys.stdout)))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Möchten Sie eine lokale Stapelverarbeitung erstellen.*'NO'$", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Você deseja gerar um rastreamento em pilha localmente.*'NO'$", sys.stdout))))
        .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Создать данные трассировки стека локально.*'NO'$", sys.stdout)))))

    pusercancel = (DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Can't continue without.*", sys.stdout)))
            .or_this(pgdbcancel))

    pabrtbefore214 = DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT)

    ddkb.add_problem(pabrtbefore214.and_this(pusercancel)
            , "Cannot say more. Processing was interrupted on you request.")

    ddkb.add_problem(pusercancel.and_this(prsyes.not_()), "D'oh! Exit status for user cancellation doesn't work!")

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

    ddkb.add_problem(pabrtbefore214.and_this(pdupid)
        , "Problem with XML RPC changes in reporter-bugzilla which has been already fixed.")

    ddkb.add_problem(pdupid, "Reading bad field from XMP RPC response in reporter-bugzilla.")

    anaconda = DDTraitPredicate(ddfa.add_reader("component", DDRegexTrait("^anaconda$", sys.stdout)))

    pshutdown = DDMissingFilePredicate("count").and_this(
            pccpp.or_this(pkoops).or_this(pxorg).or_this(ppython).or_this(pvmcore)).and_this(anaconda.not_())

    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.4",), DDVersionPredicate.LT).and_this(pshutdown)
        , "Problem has been detected while shut down and ABRT cannot handle it.")

    ddkb.add_problem(DDMissingFilePredicate("not-reportable").and_this(pshutdown)
        , "Oh Jesus! The this problem should be marked as not_reportable")

    ddkb.add_problem(pshutdown, "I wonder how someone could report this problem. It is NOT-REPOTABLE!")

    ddkb.add_problem(DDMissingFilePredicate("core_backtrace").and_this(pkoopszero)
            , "Cannot generate core backtrace from empty stacktrace. Please, submit your dmesg to crash-catcher@lists.fedorahosted.org")

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

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*fatal: HTTP response code is 50., not 200.*", sys.stdout)))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Proxy CONNECT aborted.*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*RPC failed at server.*at .* line .*", sys.stdout))))
                .or_this(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*libcurl failed to execute the HTTP POST transaction, explaining:  Failed connect to .*:443.*", sys.stdout))))
            , "Problem with bugzilla proxy. Please, try to report your problem later.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*has been locked out of this account until.*", sys.stdout)))
            , "Blocked bugzilla account. Please, wait or contact bugzilla admistrators.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("architecture", DDRegexTrait(".*armv7l.*", sys.stdout)))
            , "We are sorry but your architecture is not supporteld.")

    pbzxmrpcfail = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Adding attachments to bug -1.*", sys.stdout)))

    ddkb.add_problem(DDVersionPredicate("abrt", ("2.1.5",), DDVersionPredicate.GT).and_this(pbzxmrpcfail)
            , "Regression rhbz#980228")

    ddkb.add_problem(pbzxmrpcfail, "rhbz#980228 fixed in libreport-2.1.5-2")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*fatal: RPC failed at server.*", sys.stdout)))
            , "Some bugzilla related bug usually happening due to an invalid user request")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*XML-RPC response too large.*", sys.stdout)))
            , "Bug in reporter-bugzilla. Response must be increased.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Unable to obtain unpacked size.*", sys.stdout)))
            , "A problem in debug package on the retrace server.")

    ddkb.add_problem(DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*No segments found in coredump.*", sys.stdout)))
            , "No segments found in coredump")

    pnetwork = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Could not resolve host.*", sys.stdout))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Couldn't resolve host name.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*curl_easy_perform: Login denied.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Error while uploading: 'curl_easy_perform:.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*couldn't connect to host*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*NSS error.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*SSL.*NSS.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Connection timed out.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*I/O operation timed out.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*TCP connection reset by peer.*", sys.stdout))))

    psucureport = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*'report_uReport' завершился без ошибок.*", sys.stdout))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*'report_uReport' completed successfully.*", sys.stdout))))

    pnobthash = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*This problem does not have an uReport assigned.*", sys.stdout))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Esse problema não tem um uReport assinalado.*", sys.stdout)))).or_this(
            DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Для этой ошибки нет присоединённых микроотчётов.*", sys.stdout))))

    pinvalidjson = DDTraitPredicate(ddfa.add_reader("event_log", DDRegexTrait(".*Invalid JSON file.*", sys.stdout)))

    pemptymodules = pkoops.and_this(DDTraitPredicate(ddfa.add_reader("backtrace", DDRegexTrait(".*Modules linked in:\s*$", sys.stdout))))

    ddkb.add_problem(pinvalidjson.and_this(pemptymodules), "Bug https://github.com/abrt/satyr/issues/113 fixed in satyr > 0.9")

    # Explore the dump directory!!
    ddkb.add_problem(psucureport.and_this(pnobthash), "Reporting to bugzilla a problem which was rejected by FAF.")
    # OK cannot do more, expected behaviour
    ddkb.add_problem(pnetwork.and_this(pnobthash), "A crash without BTHASH due to network connection problems.")
    # Update database
    ddkb.add_problem(pnobthash, "No BTHASH for unknown reason!")

    ddkb.add_problem(pnetwork, "Network connection problem.")

    return ddkb
