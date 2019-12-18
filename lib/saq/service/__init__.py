# vim: sw=4:ts=4:et
#
# ACE Services
# These are wrappers around the concept of a process that executes as part of
# ACE and optionally in the background.
#

import atexit
import importlib
import logging, logging.config
import os, os.path
import resource
import shutil
import signal
import sys
import threading
import time

import psutil

import saq
from saq.error import report_exception

# the global list of services registered under this process
_registered_services = [] # of ACEService objects

def _service_signal_handler(signum, frame):
    for service in _registered_services:
        if signum == signal.SIGHUP:
            service.reload_service()
        else:
            service.stop_service()

def register_service(service):
    """Register the given service for tracking purporses."""
    assert isinstance(service, ACEService)
    global _registered_services

    # if this is the first time we register a service then we need
    # to install the signal handlers to gracefully shutdown the service
    if not _registered_services:
        logging.debug("registering signal handlers")
        signal.signal(signal.SIGTERM, _service_signal_handler)
        signal.signal(signal.SIGINT, _service_signal_handler)
        signal.signal(signal.SIGHUP, _service_signal_handler)

    # this is a bit confusing so this needs explained here
    # if you are running daemon services, then they each run in their own process
    # when ace starts up, it adds the signal handler (see above) and starts keeping track
    # of *all* the services being started
    # however, in a daemon process, when the signal is received we only want to call the shutdown
    # on ourselves
    # so if this is a deamon process, then it REPLACES the existing service rather than appending to the list
    if service.service_is_daemon:
        _registered_services = [ service ]
    else:
        _registered_services.append(service)

class ServiceAlreadyRunningError(Exception):
    """Thrown when we try to start a service that is already running."""
    pass

class ServiceDisabledError(Exception):
    """Thrown when we try to start a service that is disabled."""
    pass

SERVICE_STATUS_RUNNING = 'running'
SERVICE_STATUS_STOPPED = 'stopped'
SERVICE_STATUS_STALE = 'stale'
SERVICE_STATUS_DISABLED = 'disabled'

# NOTE
# something to remember here: note the difference between services running in threaded mode vs daemon mode
# in threaded mode you typically create a service object then use that object to both start and stop the service
# but with damon mode you typically create a service object then use that object to start the service and then exit
# (since the daemon is now running under another process)
# then later on you stop the service by either using the stop_service() function, or, by creating *another* service
# object and using stop_service() on that
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
        self.service_is_daemon = False
        # are we running execute_service on another thread?
        self.service_is_threaded = False
        # are we debugging the service?
        self.service_is_debug = False
        # does this service need to reload? (SIGHUP)
        self.service_reload_flag = False
        # does this service depend on other services?
        self.service_dependencies = get_service_dependencies(self.service_name)

        # we keep track of running services through these files 
        # NOTE services running as daemons are also tracked elsewhere
        self.service_indicator_path = os.path.join(saq.SERVICES_DIR, self.service_name)

    def execute_service(self):
        """The entry point for the service. This function is expected to start the service
           and *NOT* return until the service has completed."""
        raise NotImplementedError()

    def initialize_service_environment(self):
        """Called after new threads or processes are created."""
        pass

    def cleanup_service(self):
        pass

    def start_service(self, threaded=False, daemon=False, debug=False):
        assert threaded or daemon or debug
        # make sure the service is enable and not already running
        status = self.service_status
        if status == SERVICE_STATUS_DISABLED:
            raise ServiceDisabledError()
        elif status == SERVICE_STATUS_RUNNING:
            raise ServiceAlreadyRunningError()

        logging.info(f"starting service {self.service_name}")

        self.service_is_daemon = daemon
        self.service_is_threaded = threaded
        self.service_is_debug = debug

        # register the service for signal handlers
        # NOTE that for daemons they only need to keep track of their own service
        register_service(self)

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

    def stop_service(self):
        logging.info(f"stopping service {self.service_name}")
        self.service_shutdown_event.set()

    def wait_service(self, timeout=None):
        # we only wait if the service was started in threaded mode
        if self.service_is_threaded:
            self.service_thread.join(timeout=timeout)

    def reload_service(self):
        """Called when the service receives a SIGHUP, or can also be called manually.
           Typically used to reload configuration data."""
        service_reload_flag = True

    def sleep(self, time):
        """Sleeps for time seconds using the Event object."""
        self.service_shutdown_event.wait(time)

    def background_service(self):
        """Execute this service in the background."""

        # are we already running?
        service_status = self.service_status
        if service_status == SERVICE_STATUS_STALE:
            logging.warning(f"stale pid file for {self.service_name} - removing")
            remove_service_pid(self.service_name)
        elif service_status == SERVICE_STATUS_RUNNING:
            process = psutil.Process(get_service_pid(self.service_name))
            raise AlreadyRunningError("daemon PID file {get_service_pid_path(self.service_name)} exists and {process.name()} "
                                      "is running with pid {get_service_pid(self.service_name)}")

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

        # the pid file is written in this function
        self.execute_service_wrapper()
        sys.exit(0)

    @property
    def is_service_shutdown(self):
        """Returns True if service_stop() has been called."""
        return self.service_shutdown_event.is_set()

    def execute_service_wrapper(self):
        try:
            logging.info(f"initializing service {self.service_name} environment")
            self.initialize_service_environment()
        except Exception as e:
            logging.error(f"unable to initialize service {self.service_name}: {e}")
            report_exception()
            raise

        # for services running as a daemon (which is the normal mode of operation)
        # we allow for custom logging configurations based on the service name
        # where the path of the logging configuration file is SAQ_HOME/etc/logging_configs/service_{service_name}.ini
        if self.service_is_daemon:
            # if we haven't set up the log configuration for this service but we do
            # have a default log configuration, then copy that over and we'll use it
            service_logging_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'logging_configs', f'service_{self.service_name}.ini')
            default_service_logging_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'logging_configs', f'service_{self.service_name}.default.ini')

            if os.path.exists(default_service_logging_config_path) and not os.path.exists(service_logging_config_path):
                try:
                    shutil.copy(default_service_logging_config_path, service_logging_config_path)
                except Exception as e:
                    logging.error(f"attempted to copy {default_service_logging_config_path} to {service_logging_config_path} failed: {e}")

            # if there is a log configuration set up for this service then use that
            service_logging_config_path = os.path.join(saq.SAQ_HOME, 'etc', 'logging_configs', f'service_{self.service_name}.ini')
            if os.path.exists(service_logging_config_path):
                try:
                    logging.config.fileConfig(service_logging_config_path, disable_existing_loggers=True)
                except Exception as e:
                    logging.error(f"unable to load logging configuration: {e}")
                    raise e

        logging.info(f"starting service {self.service_name}")

        try:
            self.record_service_pid()
            if not saq.UNIT_TESTING:
                atexit.register(self.remove_service_pid)
            return self.execute_service()
        except Exception as e:
            logging.error(f"uncaught exception: {e}")
            report_exception()
            return None
        finally:
            self.cleanup_service()
            self.remove_service_pid()

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
        return get_service_status(self.service_name)

    def record_service_pid(self):
        """Record the fact that this service is now running."""
        record_service_pid(self.service_name, os.getpid())

    def remove_service_pid(self):
        """Removes the service indicator for this service."""
        remove_service_pid(self.service_name)

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

def get_service_dependencies(service_name):
    service_config = get_service_config(service_name)
    if service_config is None:
        raise ValueError(f"unknown service name {service_name}")

    # not all services have dependencies
    if 'dependencies' not in service_config:
        return []

    return [_.strip() for _ in service_config['dependencies'].split(',')]

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

def get_service_pid_path(service_name):
    """Returns the service indicator path for the given service."""
    return os.path.join(saq.SERVICES_DIR, service_name)

def record_service_pid(service_name, pid):
    """Records the service PID. Returns the path the service PID was recorded in."""
    assert isinstance(service_name, str) and service_name
    assert isinstance(pid, int) and pid

    with open(get_service_pid_path(service_name), 'w') as fp:
        fp.write(str(pid))

def remove_service_pid(service_name):
    """Removes the record of the service PID."""
    try:
        os.remove(get_service_pid_path(service_name))
    except Exception as e:
        pass

def get_service_pid(service_name):
    """Returns the PID the given service is running under, or None if the service is not running."""
    try:
        if os.path.exists(get_service_pid_path(service_name)):
            with open(get_service_pid_path(service_name), 'r') as fp:
                return int(fp.read())
    except:
        return None

def get_service_status(service_name):
    """Returns the status for the given service."""
    service_pid = get_service_pid(service_name)
    if service_pid is None:
        if not saq.CONFIG[f'service_{service_name}'].getboolean('enabled'):
            return SERVICE_STATUS_DISABLED

        return SERVICE_STATUS_STOPPED

    if service_pid > 0:
        try:
            # is this process still running?
            os.kill(service_pid, 0) 
            return SERVICE_STATUS_RUNNING
        except OSError:
            return SERVICE_STATUS_STALE

def stop_service(service_name):
    """Stops the given service by sending unix control signals to the process.
       Waits for the process to stop before returning from the function.
       Kills the process and any children processes if the process does not exit normally."""

    service_pid = get_service_pid(service_name)
    if service_pid is None:
        logging.warning(f"service {service_name} does not appear to be running")
        return True

    try:
        parent = psutil.Process(service_pid)

        logging.info("sending SIGTERM to {}".format(parent.pid))
        # this should gracefully allow the system to come to a stop
        parent.terminate()

        try:
            parent.wait(timeout=60)
            logging.info("system shut down")
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
                result = True
            except Exception as e:
                logging.error("unable to kill process {}: {}".format(parent.pid, e))

    except Exception as e:
        logging.error("unable to stop process {}: {}".format(parent, e))

    # if the service pid file still around go ahead and delete it
    remove_service_pid(service_name)
    return result
