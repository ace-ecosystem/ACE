# vim: sw=4:ts=4:et

#
# all of the engines that do stuff need to coordinate with each other
# to make sure they don't overwhelm the resources they use
# see semaphores.txt

import datetime
import ipaddress
import logging
import multiprocessing
import os
import re
import socket
import sys
import threading
import time

from math import floor
from threading import Thread, Semaphore, RLock

import saq
from saq.constants import *
from saq.error import report_exception
from saq.performance import record_metric
from saq.service import *

# this is a fall back device to be used if the network semaphore is unavailable
fallback_semaphores = {}

def initialize_fallback_semaphores():
    """This needs to be called once at the very beginning of starting ACE."""

    if fallback_semaphores:
        return

    # we need some fallback functionality for when the network semaphore server is down
    # these semaphores serve that purpose
    global_engine_instance_count = saq.CONFIG['global'].getint('global_engine_instance_count')
    for key in saq.CONFIG['service_network_semaphore'].keys():
        if key.startswith('semaphore_'):
            semaphore_name = key[len('semaphore_'):]
            # the configuration settings for the network semaphore specify how many connections
            # are allowed to a specific resource at once, globally
            # so if we unable to coordinate globally, the fall back is to divide the available
            # number of resources between all the engines evenly
            # that's what this next equation is for
            fallback_limit = int(floor(saq.CONFIG['service_network_semaphore'].getfloat(key) / float(global_engine_instance_count)))
            # we allow a minimum of one per engine
            if fallback_limit < 1:
                fallback_limit = 1

            logging.debug(f"fallback semaphore count for {semaphore_name} is {fallback_limit}")
            fallback_semaphores[semaphore_name] = LoggingSemaphore(fallback_limit)

class LoggingSemaphore(Semaphore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.count = 0
        self.count_lock = RLock()
        self.semaphore_name = None

    def acquire(self, *args, **kwargs):
        result = super().acquire(*args, **kwargs)
        if result:
            with self.count_lock:
                self.count += 1
            logging.debug(f"acquire: semaphore {self.semaphore_name} count is {self.count}")

        return result

    def release(self, *args, **kwargs):
        super(LoggingSemaphore, self).release(*args, **kwargs)
        with self.count_lock:
            self.count -= 1
        logging.debug(f"release: semaphore {self.semaphore_name} count is {self.count}")

class NetworkSemaphoreClient(object):
    def __init__(self, cancel_request_callback=None):
        # the remote connection to the network semaphore server
        self.socket = None
        # this is set to True if the client was able to acquire a semaphore
        self.semaphore_acquired = False
        # the name of the acquired semaphore
        self.semaphore_name = None
        # a failsafe thread to make sure we end up releasing the semaphore
        self.failsafe_thread = None
        # reference to the relavent configuration section
        self.config = saq.CONFIG['service_network_semaphore']
        # if we ended up using a fallback semaphore
        self.fallback_semaphore = None
        # use this to cancel the request to acquire a semaphore
        self.cancel_request_flag = False
        # OR use this function to determine if we should cancel the request
        # the function returns True if the request should be cancelled, False otherwise
        self.cancel_request_callback = cancel_request_callback

    @property
    def request_is_cancelled(self):
        """Returns True if the request has been cancelled, False otherwise.
           The request is cancelled if cancel_request_flag is True OR 
           cancel_request_callback is defined and it returns True."""
        
        return self.cancel_request_flag or ( self.cancel_request_callback is not None
                                             and self.cancel_request_callback() )

    def acquire(self, semaphore_name):
        if self.semaphore_acquired:
            logging.warning(f"semaphore {self.semaphore_name} already acquired")
            return True

        try:
            self.socket = socket.socket()
            logging.debug("attempting connection to {} port {}".format(self.config['remote_address'], self.config.getint('remote_port')))

            self.socket.connect((self.config['remote_address'], self.config.getint('remote_port')))
            logging.debug(f"requesting semaphore {semaphore_name}")

            # request the semaphore
            self.socket.sendall('acquire:{}|'.format(semaphore_name).encode('ascii'))

            # wait for the acquire to complete
            wait_start = datetime.datetime.now()

            while not self.request_is_cancelled:
                command = self.socket.recv(128).decode('ascii')
                if command == '':
                    raise RuntimeError("detected client disconnect")

                logging.debug(f"received command {command} from server")

                # deal with the possibility of multiple commands sent in a single packet
                # (remember to strip the last pipe)
                commands = command[:-1].split('|')
                if 'locked' in commands:
                    logging.debug(f"semaphore {semaphore_name} locked")
                    self.semaphore_acquired = True
                    self.semaphore_name = semaphore_name
                    self.start_failsafe_monitor()
                    return True

                elif all([x == 'wait' for x in commands]):
                    continue

                else:
                    raise ValueError(f"received invalid command {command}")

            logging.debug(f"semaphore request for {semaphore_name} cancelled")
            return False

        except Exception as e:
            logging.error(f"unable to acquire network semaphore: {e}")

            try:
                self.socket.close()
            except Exception as e:
                pass

            # use the fallback semaphore
            try:
                logging.warning(f"acquiring fallback semaphore {semaphore_name}")
                while not self.request_is_cancelled:
                    if fallback_semaphores[semaphore_name].acquire(blocking=True, timeout=1):
                        logging.debug(f"fallback semaphore {semaphore_name} acquired")
                        self.fallback_semaphore = fallback_semaphores[semaphore_name]
                        self.semaphore_acquired = True
                        self.semaphore_name = semaphore_name
                        self.start_failsafe_monitor()
                        return True
                
                return False
                    
            except Exception as e:
                logging.error(f"unable to use fallback semaphore {semaphore_name}: {e}")
                report_exception()

            return False

    def cancel_request(self):
        self.cancel_request_flag = True

    def failsafe_loop(self):
        # we start a side-thread to monitor this time the semaphore is held
        # we basically just log the fact that we still have it so we can
        # see that when we are debugging
        try:
            acquire_time = datetime.datetime.now()
            while self.semaphore_acquired:
                logging.debug("semaphore {} lock time {}".format(
                    self.semaphore_name, datetime.datetime.now() - acquire_time))

                # if we are still in network mode then send a keep-alive message to the server
                if self.fallback_semaphore is None:
                    self.socket.sendall('wait|'.encode('ascii'))

                time.sleep(3)

            logging.debug(f"detected release of semaphore {self.semaphore_name}")
                
        except Exception as e:
            logging.error(f"failsafe on semaphore {self.semaphore_name} error {e}")
            try:
                self.socket.close()
            except:
                pass

    def start_failsafe_monitor(self):
        self.failsafe_thread = Thread(target=self.failsafe_loop, name=f"Failsafe {self.semaphore_name}")
        self.failsafe_thread.daemon = True
        self.failsafe_thread.start()

    def release(self):
        if not self.semaphore_acquired:
            logging.warning(f"release called on unacquired semaphore {self.semaphore_name}")

        # are we releasing a fallback semaphore?
        if self.fallback_semaphore is not None:
            logging.debug(f"releasing fallback semaphore {self.semaphore_name}")
            try:
                self.fallback_semaphore.release()
            except Exception as e:
                logging.error(f"unable to release fallback semaphore {self.semaphore_name}: {e}")
                report_exception(e)

            # make sure we set this so that the monitor thread exits
            self.semaphore_acquired = False

            return

        try:
            # send the command for release
            logging.debug(f"releasing semaphore {self.semaphore_name}")
            self.socket.sendall("release|".encode('ascii'))

            # wait for the ok
            command = self.socket.recv(128).decode('ascii')
            if command == '':
                logging.debug("detected client disconnect")
                return

            logging.debug(f"recevied response from server: {command}")
            if command == 'ok|':
                logging.debug(f"successfully released semaphore {self.semaphore_name}")
                return
            else:
                logging.error("invalid response from server")
                return

        except Exception as e:
            logging.error(f"error trying to release semaphore {self.semaphore_name}: {e}")
        finally:
            try:
                self.socket.close()
            except Exception:
                pass

            # make sure we set this so that the monitor thread exits
            self.semaphore_acquired = False

class NetworkSemaphoreServer(ACEService):
    def __init__(self, *args, **kwargs):
        super().__init__(service_config=saq.CONFIG['service_network_semaphore'], 
                         *args, **kwargs)

        # the main thread that listens for new connections
        self.server_thread = None

        # the main listening socket
        self.server_socket = None

        # configuration settings
        if 'service_network_semaphore' not in saq.CONFIG:
            logging.error("missing configuration service_network_semaphore")
            sys.exit(1)
        
        # binding address
        self.bind_address = self.service_config['bind_address']
        self.bind_port = self.service_config.getint('bind_port')

        # source IP addresses that are allowed to connect
        self.allowed_ipv4 = [ipaddress.ip_network(x.strip()) for x in self.service_config['allowed_ipv4'].split(',')]

        # load and initialize all the semaphores we're going to use
        self.semaphores = {} # key = semaphore_name, value = Semaphore
        for key in self.service_config.keys():
            if key.startswith('semaphore_'):
                semaphore_name = key[len('semaphore_'):]
                count = self.service_config.getint(key)
                self.semaphores[semaphore_name] = LoggingSemaphore(count)
                self.semaphores[semaphore_name].semaphore_name = semaphore_name # lol
                logging.debug(f"loaded semaphore {semaphore_name} with capacity {count}")

        # we keep some stats and metrics on semaphores in this directory
        self.stats_dir = os.path.join(saq.DATA_DIR, self.service_config['stats_dir'])
        if not os.path.isdir(self.stats_dir):
            try:
                os.makedirs(self.stats_dir)
            except Exception as e:
                logging.error(f"unable to create directory {self.stats_dir}: {e}")
                sys.exit(1)

        # a thread monitors and records statistics
        self.monitor_thread = None

    def execute_service(self):
        if self.service_is_debug:
            return self.server_loop()

        self.server_thread = Thread(target=self.server_loop, name="Network Server")
        self.server_thread.start()

        self.monitor_thread = Thread(target=self.monitor_loop, name="Monitor")
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        self.server_thread.join()
        self.monitor_thread.join()

    def stop_service(self, *args, **kwargs):
        super().stop_service(*args, **kwargs)

        try:
            logging.debug("closing network socket...")
            # force the accept() call to break
            try:
                s = socket.socket()
                s.connect((self.service_config['bind_address'], self.service_config.getint('bind_port')))
                s.close()
            except:
                pass # doesn't matter...
        except Exception as e:
            logging.error(f"unable to close network socket: {e}")

    def monitor_loop(self):
        semaphore_status_path = os.path.join(self.stats_dir, 'semaphore.status')
        while not self.is_service_shutdown:
            with open(semaphore_status_path, 'w') as fp:
                for semaphore in self.semaphores.values():
                    fp.write(f'{semaphore.semaphore_name}: {semaphore.count}')

            time.sleep(1)

    def server_loop(self):
        while not self.is_service_shutdown:
            try:
                self.server_socket = socket.socket() # defaults to AF_INET, SOCK_STREAM
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((self.bind_address, self.bind_port))
                self.server_socket.listen(5)

                while not self.is_service_shutdown:
                    logging.debug(f"waiting for next connection on {self.bind_address}:{self.bind_port}")
                    client_socket, remote_address = self.server_socket.accept()
                    remote_host, remote_port = remote_address
                    logging.info(f"got connection from {remote_host}:{remote_port}")
                    if self.is_service_shutdown:
                        return

                    allowed = False
                    remote_host_ipv4 = ipaddress.ip_address(remote_host)
                    for ipv4_network in self.allowed_ipv4:
                        if remote_host_ipv4 in ipv4_network:
                            allowed = True
                            break

                    if not allowed:
                        logging.warning(f"blocking invalid remote host {remote_host}")
                        try:
                            client_socket.close()
                        except:
                            pass

                        continue

                    # start a thread to deal with this client
                    if self.service_is_debug:
                        self.client_loop(remote_host, remote_port, client_socket)
                    else:
                        t = Thread(target=self.client_loop, args=(remote_host, remote_port, client_socket), name=f"Client {remote_host}")
                        t.daemon = True
                        t.start()
                    
            except Exception as e:
                logging.error(f"uncaught exception: {e}")
                report_exception()

                # TODO clean up socket stuff to restart
                self.service_shutdown_event.wait(1)

    def client_loop(self, remote_host, remote_port, client_socket):
        remote_connection = f'{remote_host}:{remote_port}'
        try:
            logging.debug(f"started thread to handle connection from {remote_connection}")

            # read the next command from the client
            command = client_socket.recv(128).decode('ascii')
            if command == '':
                logging.debug("detected client disconnect")
                return

            logging.info(f"got command [{command}] from {remote_connection}")
            # super simple protocol
            # CLIENT SEND -> acquire:semaphore_name|
            # SERVER SEND -> wait|
            # SERVER SEND -> locked|
            # CLIENT SEND -> wait|
            # CLIENT SEND -> release|
            # SERVER SEND -> ok|
            # any invalid input or errors causes the connection to terminate

            m = re.match(r'^acquire:([^|]+)\|$', command)
            if m is None:
                logging.error(f"invalid command \"{command}\" from {remote_connection}")
                return

            semaphore_name = m.group(1)
            if semaphore_name not in self.semaphores:
                logging.error(f"invalid semaphore {semaphore_name} requested from {remote_connection}")
                return

            semaphore = self.semaphores[semaphore_name]
            semaphore_acquired = False
            request_time = datetime.datetime.now()
            try:
                while True:
                    logging.debug(f"attempting to acquire semaphore {semaphore_name}")
                    semaphore_acquired = semaphore.acquire(blocking=True, timeout=1)
                    if not semaphore_acquired:
                        logging.warning("{} waiting for semaphore {} cumulative waiting time {}".format(
                            remote_connection, semaphore_name, datetime.datetime.now() - request_time))
                        # send a heartbeat message back to the client
                        client_socket.sendall("wait|".encode('ascii'))
                        continue

                    logging.info(f"acquired semaphore {semaphore_name}")
                    client_socket.sendall("locked|".encode('ascii'))
                    break

                # now wait for either the client to release the semaphore
                # or for the connection to break
                release_time = datetime.datetime.now()
                while True:
                    command = client_socket.recv(128).decode('ascii')
                    if command == '':
                        logging.debug("detected client disconnect")
                        return

                    logging.debug("got command {} from {} semaphore capture time {}".format(
                        command, remote_connection, datetime.datetime.now() - release_time))

                    if not command.endswith('|'):
                        logging.error("missing pipe at end of command")
                        return

                    # deal with the possibility of multiple commands sent in a single packet
                    # strip the last pipe
                    # XXX not 100% sure on this but here it is
                    command = command[:-1]
                    commands = command.split('|')
                    if 'release' in commands:
                        # send the OK to the client
                        client_socket.sendall('ok|'.encode('ascii'))
                        break

                    if all([x == 'wait' for x in commands]):
                        logging.debug("got wait command(s)...")
                        continue

                    logging.error(f"invalid command {command} from connection {remote_connection}")
                    return
            finally:
                try:
                    if semaphore_acquired:
                        semaphore.release()
                        logging.info(f"released semaphore {semaphore_name}")
                except Exception as e:
                    logging.error(f"error releasing semaphore {semaphore_name}: {e}")

        except Exception as e:
            logging.error(f"uncaught exception for {remote_connection}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
