# vim: sw=4:ts=4:et
#
# ACE Services
# These are wrappers around the concept of a process that executes as part of
# ACE and optionally in the background.
#

import importlib
import logging, logging.config
import os, os.path
import resource
import signal
import threading
import time

import psutil

import saq
from saq.error import report_exception

class ServiceAlreadyRunningError(Exception):
    """Thrown when we try to start a service that is already running."""
    pass

class ServiceDisabledError(Exception):
    """Thrown when we try to start a service that is disabled."""
    pass

# possible daemon states
DAEMON_STATUS_STOPPED = 'stopped'
DAEMON_STATUS_STALE = 'stale'
DAEMON_STATUS_RUNNING = 'running'

# TODO - also record the psutil.Process.(whatever) in the daemon pid file
#        so that you can tell if the daemon dies and another process started using the same PID

def get_daemon_pid_path(daemon_name):
    """Returns the path to the PID file for the given daemon."""
    return os.path.join(saq.DAEMON_DIR, daemon_name)

def get_daemon_pid(daemon_name):
    """Returns the current PID of the daemon, or None if it cannot be found."""
    try:
        daemon_pid_path = get_daemon_pid_path(daemon_name)
        if not os.path.exists(daemon_pid_path):
            return None

        with open(daemon_pid_path, 'r') as fp:
            return int(fp.read())

    except Exception as e:
        logging.error(f"unable to read daemon pid file {daemon_pid_path}: {e}")
        return None

def get_daemon_status(daemon_name):
    """Returns the status of the given daemon. One of the following values will be returned.
       DAEMON_STATUS_STOPPED - the daemon is not running
       DAEMON_STATUS_RUNNING - the daemon is running
       DAEMON_STATUS_STALE - the daemon pid file exists but the daemon is not running"""

    pid = get_daemon_pid(daemon_name)
    if pid is None:
        return DAEMON_STATUS_STOPPED
    
    if pid > 0:
        try:
            # is this process still running?
            os.kill(pid, 0) 
            return DAEMON_STATUS_RUNNING
        except OSError:
            daemon_pid_path = get_daemon_pid_path(daemon_name)
            return DAEMON_STATUS_STALE

def kill_daemon(daemon_name):

    daemon_pid_path = os.path.join(saq.DAEMON_DIR, daemon_name)
    if not os.path.exists(daemon_pid_path):
        logging.warning(f"daemon file {daemon_pid_path} does not exist (process not running?)")
        return False

    deamon_pid = None
    try:
        with open(daemon_pid_path, 'r') as fp:
            daemon_pid = int(fp.read())
    except Exception as e:
        logging.error(f"cannot read PID from {daemon_pid_path}: {e}")
        return False

    result = False

    try:
        parent = psutil.Process(daemon_pid)

        logging.info("sending SIGTERM to {}".format(parent.pid))
        # this should gracefully allow the system to come to a stop
        parent.terminate()

        try:
            parent.wait(timeout=60)
            logging.info("system shut down")
            os.remove(daemon_pid_path)
            result = True
        except Exception as e:
            logging.error("unable to terminate process {}: {}".format(parent.pid, e))

            # but if it doesn't work then we walk the tree kill all processes
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                    logging.info("killed child process {}".format(child.pid))
                except Exception as e:
                    logging.error("unable to kill child process {}: {}".format(child, e))

            try:
                parent.kill()
                os.remove(daemon_pid_path)
                result = True
            except Exception as e:
                logging.error("unable to kill process {}: {}".format(parent.pid, e))

    except Exception as e:
        logging.error("unable to stop process {}: {}".format(parent, e))

    return result

SERVICE_STATUS_RUNNING = 'running'
SERVICE_STATUS_STOPPED = 'stopped'
SERVICE_STATUS_STALE = 'stale'
SERVICE_STATUS_DISABLED = 'disabled'

# NOTE
# something to remember here: note the difference between services running in threaded mode vs daemon mode
# in threaded mode you typically create a service object then use that object to both start and stop the service
# but with damon mode you typically create a service object then use that object to start the service and then exit
# (since the daemon is now running under another process)
# then later on you stop the service by either using the kill_daemon() function, or, by creating *another* service
# object and using stop_service() on that (which just callsl kill_daemon() anyways)
# so with threaded services you hold on to the reference to the service for the lifetime
# but not so with deamon services

class ACEService(object):
    def __init__(self, service_config=None):
        if service_config is None:
            raise RuntimeError(f"missing service configuration for {self}")

        # reference to the configuration section for this service
        self.service_config = service_config
        # when a service starts it starts on it's own new thread 
        # that way you can start multiple services on the same process (if needed)
        self.service_thread = None
        # primary shutdown event, used to perform a controlled shutdown
        self.service_shutdown_event = threading.Event()
        # are we running as a daemon?
        self.service_is_daemon = os.path.exists(get_daemon_pid_path(self.service_name))
        # are we running execute_service on another thread?
        self.service_is_threaded = False
        # are we debugging the service?
        self.service_is_debug = False

    def execute_service(self):
        raise NotImplementedError()

    def initialize_service_environment(self):
        """Called after new threads or processes are created."""
        pass

    def cleanup_service(self):
        pass

    def register_signal_handlers(self):
        """Registers signal handlers for SIGTERM and SIGINT to gracefully shut down the service."""
        def _handler(signum, frame):
            logging.warning(f"caught signal {signal.Signals(signum).name}")
            self.stop_service()

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)

    def start_service(self, threaded=False, daemon=False, debug=False):
        if not self.service_enabled:
            raise ServiceDisabledError()

        logging.info(f"starting service {self.service_name}")

        self.service_is_daemon = daemon
        self.service_is_threaded = threaded
        self.service_is_debug = debug

        self.register_signal_handlers()

        if self.service_is_daemon:
            return self.background_service()
        elif self.service_is_threaded :
            # only difference with threaded mode is it executes the primary function on another thread
            self.service_thread = threading.Thread(target=self.execute_service_wrapper, 
                                                   name=f"ACE Service Thread {self.service_name}")
            self.service_thread.start()
            return self.service_thread
        else:
            return self.execute_service_wrapper()

    def debug_service(self):
        return self.start_service(debug=True)

    def stop_service(self, daemon=False):
        self.service_shutdown_event.set()
        if daemon:
            return kill_daemon(self.service_name)

    def wait_service(self, daemon=False, timeout=None):
        # only the threaded service can wait for join()
        # for daemon processes the kill_daemon() function waits using psutil
        if self.service_is_threaded:
            self.service_thread.join(timeout=timeout)

    def background_service(self):
        # are we already running?
        service_status = self.service_status
        if service_status == SERVICE_STATUS_STALE:
            logging.warning(f"stale pid file for {self.service_name} - removing")
            os.remove(get_daemon_pid_path(self.service_name))
        elif service_status == SERVICE_STATUS_RUNNING:
            process = psutil.Process(get_daemon_pid(self.service_name))
            raise AlreadyRunningError("deamon PID file {daemon_pid_path} exists and {process.name()} "
                                      "is running with pid {pid}")

        daemon_pid_path = os.path.join(saq.DAEMON_DIR, self.service_name)
        pid = None

        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        try:
            pid = os.fork()
        except OSError as e:
            logging.error(f"{e.strerror} ({e.errno})")
            return False

        if pid == 0:
            os.setsid()
            try:
                pid = os.fork()
            except OSError as e:
                logging.error(f"{e.strerror} ({e.errno})".format(e.strerror, e.errno))
                return False

            if pid > 0:
                # write the pid to a file
                with open(daemon_pid_path, 'w') as fp:
                    fp.write(str(pid))

                print("started background process {}".format(pid))
                logging.info(f"started daemon service {self.service_name} on {pid}")
                os._exit(0)
            else:
                logging.info(f"initializing daemon service {self.service_name}")
        else:
            logging.info(f"started session owner for {self.service_name} on {pid}")
            return True

        # TODO: reconfigure logging for this service

        # if any of stdin, stdout or stderr are TTY (terminal output)
        # then close them and redirect them to /dev/null

        if (hasattr(os, "devnull")):
            REDIRECT_TO = os.devnull
        else:
            REDIRECT_TO = "/dev/null"

        if os.isatty(0):
            os.close(0)
            os.open(REDIRECT_TO, os.O_RDWR)

        if os.isatty(1):
            os.close(1)
            os.open(REDIRECT_TO, os.O_RDWR)

        if os.isatty(2):
            os.close(2)
            os.open(REDIRECT_TO, os.O_RDWR)

        self.execute_service_wrapper()
        sys.exit(0)

    @property
    def is_service_shutdown(self):
        """Returns True if service_stop() has been called."""
        return self.service_shutdown_event.is_set()

    def execute_service_wrapper(self):
        try:
            self.initialize_service_environment()
        except Exception as e:
            logging.error(f"unable to initialize service {self.service_name}: {e}")
            report_exception()
            raise

        try:
            return self.execute_service()
        except Exception as e:
            logging.error(f"uncaught exception: {e}")
            report_exception()
            return None
        finally:
            self.cleanup_service()

        if self.service_is_daemon:
            os._exit(0)

    @property   
    def service_enabled(self):
        """Returns True if the service is enabled. A service must be enabled before it can be started."""
        return self.service_config.getboolean('enabled')

    @property
    def service_name(self):
        """Returns the name of the service."""
        return self.service_config.name[len('service_'):]

    @property
    def service_description(self):
        """Returns a useful description of the service."""
        return self.service_config['description']

    @property
    def service_status(self):
        if self.service_is_daemon:
            return self.service_status_daemon
        else:
            return self.service_status_threaded

    @property
    def service_status_daemon(self):
        daemon_status = get_daemon_status(self.service_name)
        if daemon_status == DAEMON_STATUS_RUNNING:
            return SERVICE_STATUS_RUNNING
        elif daemon_status == DAEMON_STATUS_STALE:
            return SERVICE_STATUS_STALE
        elif daemon_status == DAEMON_STATUS_STOPPED:
            if not self.service_enabled:
                return SERVICE_STATUS_DISABLED
            
        return SERVICE_STATUS_STOPPED

    @property
    def service_status_threaded(self):
        if self.service_thread is not None:
            if self.service_thread.is_alive():
                return SERVICE_STATUS_RUNNING
                    
        if not self.service_enabled:
            return SERVICE_STATUS_DISABLED

        return SERVICE_STATUS_STOPPED

    @property
    def service_daemon_pid(self):
        return get_daemon_pid(self.service_name)

def get_all_service_names():
    """Returns a sorted list of all the services names currently being tracked."""
    # get the list of all the service_ configuration items
    # return a sorted unique list of the services
    return sorted(list(set([_[len('service_'):] for _ in saq.CONFIG.sections() if _.startswith('service_')])))

def get_service_config(service_name):
    """Returns the config section (from saq.CONFIG) for the given service name,
       or None if the service is unknown."""
    try:
        return saq.CONFIG[f'service_{service_name}']
    except KeyError:
        return None

def get_service_class(service_name):
    """Returns the class definition for the given service name,
       or None if the service is unknown."""
    config = get_service_config(service_name)
    if config is None:
        return None

    module_name = config['module']
    try:
        _module = importlib.import_module(module_name)
    except Exception as e:
        logging.error(f"unable to import service module {module_name}: {e}")
        return None

    class_name = config['class']
    try:
        return getattr(_module, class_name)
    except AttributeError as e:
        logging.error("class {} does not exist in module {} in service {} config".format(
                      class_name, module_name, service_name))
        return None
