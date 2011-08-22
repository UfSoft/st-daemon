# -*- coding: utf-8 -*-
"""
    ST-Daemon
    ~~~~~~~~~

    Simple library to help setting up a python application up to the point
    of daemonizing it(or not)

    :copyright: © 2011 UfSoft.org - :email:`Pedro Algarvio (pedro@algarvio.me)`
    :license: BSD, see LICENSE for more details.
"""

__version__         = '0.9'
__package_name__    = 'ST-Daemon'
__summary__         = "Python's standard logging helpers"
__author__          = 'Pedro Algarvio'
__email__           = 'pedro@algarvio.me'
__license__         = 'BSD'
__url__             = 'http://dev.ufsoft.org/projects/daemon'
__description__     = __doc__

import os
import sys
import errno
import signal
import pwd
import grp
import psi.process
from psi.process import NoSuchProcessError
from os import path
from optparse import OptionParser
from st import log #import set_logger_level, setup_logging, LOG_LEVELS

class BaseOptionParser(OptionParser):
    def __init__(self, package_name, package_version):
        OptionParser.__init__(
            self, version=("%s:%%prog " % package_name) + package_version
        )

        self.add_option('-p', '--pidfile', help="Pidfile path",
                        default=None, metavar='PIDFILE_PATH')
        self.add_option('-d', '--detach', action="store_true",
                        default=False, dest="detach_process",
                        help="Detach process(daemonize) Default: %default")
        self.add_option('-u', '--uid', default=os.getuid(),
                        help="User ID. Default: %s(%%default)" %
                              pwd.getpwuid(os.getuid()).pw_name)
        self.add_option('-g', '--gid', default=os.getgid(),
                        help="Group ID. Default: %s(%%default)" %
                        grp.getgrgid(os.getgid()).gr_name)
        self.add_option('-w', '--working-dir', default=os.getcwd(),
                        help="The working dir the process should change to. "
                             "Default: %default")
        self.add_option('-l', '--logfile', help="Log file path")
        self.add_option('-L', '--loglevel', default="info", choices=sorted(
                            log.LOG_LEVELS, key=lambda k: log.LOG_LEVELS[k]
                        ), help="The desired logging level. Default: %default")

class BaseDaemon(object):

    LOG_FMT = '%(asctime)s,%(msecs)03.0f [%(name)-15s][%(levelname)-8s] %(message)s'

    def __init__(self, working_directory=os.getcwd(), pidfile=None,
                 detach_process=True, uid=None, gid=None, logfile=None,
                 loglevel="info", process_name=None, exit_timeout=5):

        self.__pid = None
        self.__exiting = False
        self.process_name = process_name
        self.exit_timeout = exit_timeout

        self.working_directory = working_directory

        if pidfile:
            pidfile = os.path.abspath(pidfile)
        self.pidfile = pidfile

        self.detach_process = detach_process
        self.uid = uid
        self.gid = gid
        if logfile:
            logfile = os.path.abspath(logfile)
        self.logfile = logfile
        self.loglevel = loglevel

    def prepare(self):
        if self.working_directory and not path.isdir(self.working_directory):
            print "Working directory %s does not exist" % self.working_directory
            sys.exit(1)

        if self.detach_process and not self.pidfile:
            print("You're trying to detach the daemon but you're not passing "
                  "the pidfile name.")
            sys.exit(1)

        if self.uid and isinstance(self.uid, basestring):
            try:
                self.uid = int(self.uid)
            except:
                pw = pwd.getpwnam(self.uid)
                if pw:
                    self.uid = pw.pw_uid
        if self.gid and isinstance(self.gid, basestring):
            try:
                self.gid = int(self.gid)
            except:
                gp = grp.getgrnam(self.gid)
                if gp:
                    self.gid = gp.gr_gid

    def check_pid(self):
        if not self.pidfile:
            return
        if os.path.isfile(self.pidfile):
            try:
                pid = int(open(self.pidfile, 'r').read())
                process = psi.process.Process(pid=pid)
                if self.process_name in process.args:
                    print('Instance already running with pidfile %d' %
                          process.pid)
                    sys.exit(1)
                else:
                    os.unlink(self.pidfile)
            except NoSuchProcessError:
                os.unlink(self.pidfile)
            for process in psi.process.ProcessTable().values():
                if process.pid == os.getpid():
                    # This is us, continue
                    continue
                if self.process_name in process.args:
                    print('Instance already running with pidfile %d' %
                          process.pid)
                    sys.exit(1)

    def write_pid(self):
        if self.__pid is None:
            self.__pid = os.getpid()
        if not self.pidfile:
            return
        self.check_pid()
        f = open(self.pidfile,'wb')
        f.write(str(self.__pid))
        f.close()

    def remove_pid(self):
        """
        Remove the specified PID file, if possible.  Errors are logged, not
        raised.

        @type pidfile: C{str}
        @param pidfile: The path to the PID tracking file.
        """
        if self.pidfile is None or not os.path.isfile(self.pidfile):
            return
        import logging
        log = logging.getLogger('st.daemon')
        try:
            os.unlink(self.pidfile)
        except OSError, e:
            if e.errno == errno.EACCES or e.errno == errno.EPERM:
                log.warn("No permission to delete pid file")
            else:
                log.error("Failed to unlink PID file: %s", e)
        except Exception, e:
            log.error("Failed to unlink PID file: %s", e)

    def drop_privileges(self):
        import logging
        log = logging.getLogger('st.daemon')
        if self.uid or self.gid:
            log.trace("Dropping privileges")
        if self.uid:
            try:
                log.trace("Setting UID to %s", self.uid)
                os.setuid(self.uid)
            except Exception, err:
                log.error(err)
        if self.gid:
            try:
                log.trace("Setting GID to %s", self.gid)
                os.setgid(self.gid)
            except Exception, err:
                log.error(err)

    def daemonize(self):
        if not self.detach_process:
            return
        import logging
        logging.getLogger('st.daemon').trace("Forking process")
        os.umask(077)
        # See http://www.erlenstar.demon.co.uk/unix/faq_toc.html#TOC16
        if os.fork():   # launch child and...
            os._exit(0) # kill off parent
        os.setsid()
        if os.fork():   # launch child and...
            os._exit(0) # kill off parent again.
        null = os.open('/dev/null', os.O_RDWR)
        for i in range(3):
            try:
                os.dup2(null, i)
            except OSError, e:
                if e.errno != errno.EBADF:
                    raise
        os.close(null)
        logging.getLogger('st.daemon').trace("Process forked!")

    def setup_logging(self):
        log.setup_logging()
        log.setup_console_logger(self.loglevel, fmt=self.LOG_FMT)
        if self.logfile:
            log.setup_logfile_logger(self.loglevel, self.logfile, fmt=self.LOG_FMT)
        import logging
        logging.getLogger('st.daemon').trace("Logging setup!")

    def change_working_dir(self):
        import logging
        logging.getLogger('st.daemon').trace("Changing working directory...")
        os.chdir(self.working_directory)
        logging.getLogger('st.daemon').trace("Working directory is now %r",
                                             os.getcwd())

    def run_daemon(self):
        self.check_pid()
        self.setup_logging()
        self.prepare()
        import logging
        logging.getLogger('st.daemon').trace("on run_daemon")
        self.daemonize()
        self.change_working_dir()
        self.drop_privileges()
        self.write_pid()
        if self.process_name:
            try:
                import procname
                procname.setprocname(self.process_name)
            except ImportError:
                pass
        signal.signal(signal.SIGTERM, self._exit)   # Terminate
        signal.signal(signal.SIGINT, self._exit)    # Interrupt
        try:
            self.run()
        except KeyboardInterrupt:
            os.kill(self.__pid, signal.SIGTERM)

    def run(self):
        raise NotImplementedError

    def exit(self):
        pass

    def _exit(self, ssignal, frame):
        import logging
        if not self.__exiting:
            def too_long(sig, frm):
                logging.getLogger('st.daemon').info(
                    "Taking too long to exit(>%d secs). Commit suicide!!!",
                    self.exit_timeout
                )
                self.remove_pid()
                logging.shutdown()
                try:
                    os.kill(self.__pid, signal.SIGKILL)
                except OSError, err:
                    logging.getLogger('st.daemon').exception(
                        "Failed to commit suicide: %s", err
                    )
            # Setup an alarm signal so that if taking too long, commit suicide
            signal.signal(signal.SIGALRM, too_long)
            signal.alarm(self.exit_timeout) # We have X secs to exit properly
            logging.getLogger('st.daemon').info("Exiting...")
            self.__exiting = True
            # Ignore any further signaling
            signal.signal(ssignal, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            self.exit()

            logging.getLogger('st.daemon').info("Exited!!!")
            logging.shutdown()
            self.remove_pid()
            os._exit(1)

    @classmethod
    def cli(cls):
        raise NotImplementedError
