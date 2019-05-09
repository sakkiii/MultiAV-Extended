import time
import threading
import json
import uuid
import os
import time
import random
import datetime

from rwlock import RWLock
from promise import Promise
from subprocess import check_output, CalledProcessError
from threading import Event

from multiav.exceptions import CreateDockerMachineMachineException
from multiav.multiactionpromise import MultiActionPromise
from multiav.promiseexecutorpool import PromiseExecutorPool
from multiav.safeconfigparserextended import SafeConfigParserExtended
from multiav.dockerabstraction import LocalStaticDockerMachine, LocalDynamicDockerMachine, DockerMachineMachine, DockerContainer, DockerMachine

DOCKER_NETWORK_NO_INTERNET_NAME = "multiav-no-internet-bridge"
DOCKER_NETWORK_INTERNET_NAME = "multiav-internet-bridge"
  
#-----------------------------------------------------------------------
class ScannerStrategy:
    def __init__(self, config_name, initial_scan_time_average = 70):
        self._config_name = config_name
        self._event_subscribers = dict()

        # statistics in seconds
        self.scan_time_average = (1, initial_scan_time_average)
        self._scan_time_lock = RWLock()
        self._get_average_scan_time()

        self._read_config()
    
    def _read_config(self):
        parser = SafeConfigParserExtended()
        parser.optionxform = str
        parser.read(self._config_name)
        self.cfg_parser = parser

    def _add_scan_time(self, scan_time):
        with self._scan_time_lock.writer_lock:
            new_scan_amount = self.scan_time_average[0] + 1
            new_scan_average = ((self.scan_time_average[1] * self.scan_time_average[0]) + scan_time) / new_scan_amount
            #print("_add_scan_time: old amount: {0} old average: {1} new amount: {2} new average: {3}".format(self.scan_time_average[0], self.scan_time_average[1], new_scan_amount, new_scan_average))
            self.scan_time_average = (new_scan_amount, new_scan_average)

    def _get_average_scan_time(self):
        with self._scan_time_lock.reader_lock:
            #print("_get_average_scan_time Sample Size: {0} Avg: {1}".format(self.scan_time_average[0], self.scan_time_average[1]))
            return int(self.scan_time_average[1])

    def _scan_internal(self, engine, file_buffer):
        try:
            # measure scan time
            start_time = time.time()

            self._pre_scan(engine, file_buffer)
            
            # set container for scan
            engine.container, reduce_scan_time_by = self._get_container_for_scan(engine, file_buffer)

            print("[{0}] Scanning {1} using {2} on container {3} on machine {4}".format(engine.name, file_buffer, engine.name, engine.container.id, engine.container.machine.id))
            res = engine.scan(file_buffer)

            res["name"] = engine.name
            res["plugin_type"] = engine.plugin_type.value
            res["speed"] = engine.speed.value
            res["has_internet"] = engine.container_requires_internet
            
            if "error" in res:
                print("[{0}] Scan failed. Error: {1}".format(engine.name, res["error"]))
            else:
                print("[{0}] Scan complete.".format(engine.name))
            
            self._post_scan(engine, file_buffer)
            
            # measure scan time
            scan_time = time.time() - start_time - reduce_scan_time_by

            self._add_scan_time(scan_time)
            print("[{0}] Scan time: {1}s seconds. New average: {2}s".format(engine.name, scan_time, self._get_average_scan_time()))

            return res
        except Exception as e:
            print("[{0}] Scan internal error: {1}".format(engine.name, e))
            return {
                "name": engine.name,
                "error": "{0}".format(e),
                "engine": "",
                "updated": "",
                "plugin_type": engine.plugin_type.value,
                "speed": engine.speed.value,
                "has_internet": engine.container_requires_internet
            }
    
    def _rise_event(self, event, file_to_scan, *args, **kargs):
        #print("_rise_event: {0} for file: {1}".format(event, file_to_scan))
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            for handler in self._event_subscribers[event][file_to_scan]:
                handler(*args, **kargs)

    def on(self, event, file_to_scan, handler):
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            self._event_subscribers[event][file_to_scan].append(handler)
        else:
            self._event_subscribers[event] = {file_to_scan: [handler]}
            #print(self._event_subscribers)
    
    def unsubscribe_event_handler(self, event, file_to_scan, handler):
        if event in self._event_subscribers and file_to_scan in self._event_subscribers[event]:
            self._event_subscribers[event][file_to_scan].remove(handler)

    def _pre_scan(self, engine, file_to_scan):
        self._rise_event("pre", file_to_scan, engine, file_to_scan)

    def _post_scan(self, engine, file_to_scan):
        self._rise_event("post", file_to_scan, engine, file_to_scan)

    def startup(self, engines):
        self.engine_classes = []
        for engine in engines:
            self.engine_classes.append(engine)
        
        self._startup()
    
    def _startup(self):
        # abstract
        pass
    
    def _get_container_for_scan(self, engine, file_to_scan):
        #abstract
        pass

    def scan(self, engine, file_buffer):
        # abstract
        pass
    
    def update(self):
        # abstract
        pass
    
    def get_signature_version(self, engine):
        # abstract
        pass

    def get_statistics(self):
        # abstract
        pass

#-----------------------------------------------------------------------
class LocalDockerStrategy(ScannerStrategy):
    def __init__(self, config_name, initial_scan_time_average = 70):
        ScannerStrategy.__init__(self, config_name, initial_scan_time_average)
        self.DOCKER_NETWORK_NO_INTERNET_NAME = DOCKER_NETWORK_NO_INTERNET_NAME
        self.DOCKER_NETWORK_INTERNET_NAME = DOCKER_NETWORK_INTERNET_NAME
        self.machine = None

    def _start_containers(self, engines):
        for engine in engines:
            if engine.is_disabled():
                continue
            
            if not self.machine.create_container(engine):
                return False
        return True
    
    def _startup(self):
        self.machine = LocalStaticDockerMachine(self.cfg_parser, self.engine_classes, id_overwrite="localhost")
        
    def _get_container_for_scan(self, engine, file_to_scan):
        # search for a free spot on the local machine
        reduce_scan_time_by = 0
        container = self.machine.try_do_scan(engine, file_to_scan)

        return container, reduce_scan_time_by

    def scan(self):
        # abstract
        pass

    def update(self):
        return self.machine.update()

    def get_signature_version(self, engine):
        containers = self.machine.find_containers_by_engine(engine)

        if len(containers) == 0:
            return "-"
        
        for container in containers:
            if container.is_running():
                return containers[0].get_signature_version()
        
        return "-"
    
    def get_statistics(self):
        # asbtract
        pass

#-----------------------------------------------------------------------
class LimitedLocalDockerStrategy(LocalDockerStrategy):
    def __init__(self, config_name, num_threads, initial_scan_time_average = 70):
        LocalDockerStrategy.__init__(self, config_name, initial_scan_time_average)

        # use thread pool to handle overload without scaling
        self.pool = PromiseExecutorPool(num_threads)
        print("LocalDockerStrategy: initialized thread pool using {0} threads".format(num_threads))
        
    def scan(self, plugin, file_buffer):
        scan_promise = self.pool.add_task(self._scan_internal, plugin, file_buffer)
        return scan_promise

    def get_statistics(self):
        statistics = {
            "strategy_name": "LimitedLocalDockerStrategy",
            "worker_threads": self.pool.get_worker_amount(),
            "queue_size": self.pool.get_queue_size()
        }
        return statistics
    
#-----------------------------------------------------------------------
class JustRunLocalDockerStrategy(LocalDockerStrategy):
    def __init__(self, config_name, initial_scan_time_average = 70):
        LocalDockerStrategy.__init__(self, config_name, initial_scan_time_average)

        # thread array, not limited in size
        self.threads = []

    def _scan_promise_wrapper(self, resolve, reject, engine, file_buffer):
        def fn():
            try:
                res = self._scan_internal(engine, file_buffer)
                resolve(json.dumps(res))
            except Exception as e:
                print("[{1}] _scan_promise_wrapper exception: {0}".format(e, engine.name))
                reject(e)
            finally:
                # make sure to remove thread from running list
                self.threads.remove(thread)
        
        thread = threading.Thread(target=fn)
        self.threads.append(thread)
        thread.start()

    def scan(self, plugin, file_buffer):
        scan_promise = Promise(
            lambda resolve, reject: self._scan_promise_wrapper(resolve, reject, plugin, file_buffer)
        )
        return scan_promise

    def get_statistics(self):
        statistics = {
            "strategy_name": "JustRunLocalDockerStrategy",
            "worker_threads": len(self.threads)
        }
        return statistics

#-----------------------------------------------------------------------       
class AutoScaleDockerStrategy(ScannerStrategy):
    def __init__(self, config_name, max_machines, max_containers_per_machine, max_scans_per_container, min_machines = 1, initial_scan_time_average = 70, expected_machine_startup_time = 130, minimal_machine_run_time = 480):
        ScannerStrategy.__init__(self, config_name, initial_scan_time_average)
        # variables
        self.expected_machine_startup_time = expected_machine_startup_time
        self.minimal_machine_run_time = minimal_machine_run_time
        self.min_machines = min_machines

        # locks
        self._machine_lock = RWLock()
        self._worker_lock = RWLock()
        self._machines_starting = dict() # Event = amount of workers waiting

        # use thread pool to handle overload when maxed out scaling => tasks will stay in queue
        self._min_workers = min_machines * max_containers_per_machine * max_scans_per_container
        self._max_workers = max_machines * max_containers_per_machine * max_scans_per_container
        self.pool = PromiseExecutorPool(self._min_workers, self._max_workers)
        print("AutoScaleDockerStrategy: initialized thread pool using {0} threads (max: {1})".format(self._min_workers, self._max_workers))

        self._machines = []
        self.max_machines = max_machines
        self.max_containers_per_machine = max_containers_per_machine
        self.max_scans_per_container = max_scans_per_container
        print("AutoScaleDockerStrategy: initialized using min_machines: {0} max_machines: {1} max_containers_per_machine: {2} max_scans_per_container: {3}".format(min_machines, max_machines, max_containers_per_machine, max_scans_per_container))

    def _execute_command(self, command):
        try:
            output = check_output(command.split(" "))
        except CalledProcessError as e:
            output = e.output
        
        return str(output.decode("utf-8"))

    def _list_docker_machines(self):
        cmd = "docker-machine ls"
        response = self._execute_command(cmd)
        machines = list(map(lambda x: list(filter(lambda q: q != "", str(x).split(" "))), response.split("\n")[1:]))
        # [['multiav-test', '-', 'openstack', 'Running', 'tcp://10.0.0.51:2376', 'v18.09.3'], ...]
        return machines

    def _startup(self):
        # check for running machines
        started_machine_counter = 0
        running_machines = self._list_docker_machines()
        for machine in running_machines:
            # create instance for handling
            if len(machine) == 0:
                continue

            never_shutdown = started_machine_counter < self.min_machines
            instance = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, create_machine = False, minimal_machine_run_time = self.minimal_machine_run_time, id_overwrite = machine[0], never_shutdown=never_shutdown)

            # descide what to do
            if not "Running" in machine:
                print("detected running machine {0} in ERRORNEOUS state!".format(machine[0]))
                if not instance.try_shutdown():
                    print("tried to clean up machine {0} but failed. please clean up manually!".format(machine[0]))
                    continue
                
                print("machine {0} removed to regain a clean state...".format(machine[0]))
            else:
                print("detected running machine {0} in operational state".format(machine[0]))
                self._machines.append(instance)
                started_machine_counter += 1
                print("readding machine {0} to the list of machines now...".format(machine[0]))
        
        machine_count = len(self._machines)
        if machine_count != 0:
            # handle workers for possible newly detected machines
            with self._worker_lock.writer_lock:
                current_worker_amount = self.pool.get_worker_amount()
                required_workers_for_machines = machine_count * self.max_containers_per_machine * self.max_scans_per_container
                required_workers_for_machines = self._max_workers if required_workers_for_machines > self._max_workers else required_workers_for_machines

                workers_to_add = required_workers_for_machines - current_worker_amount
                if workers_to_add > 0:
                    print("increasing workers by {0} as {1} running machines were detected.".format(workers_to_add, machine_count))
                    self.pool.add_worker(amount=workers_to_add)
                
            print("readded {0} machines which were already runnning...".format(machine_count))

        # do we need to start machines to satisfy min_machines requirement?
        if machine_count < self.min_machines:
            amount_of_machines_to_start = self.min_machines - machine_count
            print("starting {0} machines due to min_machines requirement now...".format(amount_of_machines_to_start))
            for i in range(0, amount_of_machines_to_start):
                if self._create_machine(never_shutdown=True) == None:
                    print("could not create machine on first try. retrying now...")
                    if self._create_machine(never_shutdown=True) == None:
                        raise CreateDockerMachineMachineException()

    def _post_scan(self, engine, file_path):
        try:
            # call super class
            ScannerStrategy._post_scan(self, engine, file_path)

            # remove scan from container
            print("_post_scan: removing scan {0} from container {1}".format(file_path, engine.container.id))
            engine.container.remove_scan(file_path)

            # remove scan from machine if required
            print("checking if we need to cleanup the scan file {1} on the target machine {0}".format(file_path, engine.container.machine.id))
            if len(engine.container.machine.find_scans_by_file_path(file_path)) == 0:
                print("removing file {0} from machine {1} as its not used by a scan anymore".format(file_path, engine.container.machine.id))
                engine.container.machine.remove_file_from_machine_tmp_dir(file_path)
            
            # remove / stop container if needed
            if self.max_scans_per_container == 1:
                engine.container.machine.remove_container(engine.container)
            
        except Exception as e:
            print("_post_scan Exception: {0}".format(e))
            
    def _create_machine(self, never_shutdown=False):
            if len(self._machines) + 1 > self.max_machines:
                print("create machine called but limit reached")
                return None
            
            try:
                with self._machine_lock.writer_lock:
                    startup_event = Event()
                    self._machines_starting[startup_event] = 0

                print("starting new machine...")
                machine = DockerMachineMachine(self.cfg_parser, self.engine_classes, self.max_containers_per_machine, self.max_scans_per_container, True, self.minimal_machine_run_time, execute_startup_checks=True, never_shutdown=never_shutdown)
                machine.on("shutdown", self._on_machine_shutdown)
                print("New machine {0} started!".format(machine.id))

                with self._machine_lock.writer_lock:
                    self._machines.append(machine)
                    startup_event.set()
                    del self._machines_starting[startup_event]
                
                return machine
            except CreateDockerMachineMachineException as e:
                print(e)
                return None
        
    def _on_machine_shutdown(self, machine):
        with self._machine_lock.writer_lock:
            print("_on_machine_shutdown")
            self.pool.remove_workers(self.max_containers_per_machine * self.max_scans_per_container)
            self._machines.remove(machine)
            print("removed machine {0}!".format(machine.id))

    def _get_container_for_scan(self, engine, file_path):
        container = None
        machine = None
        reduce_scan_time_by = False

        machine_count = len(self._machines)

        # search for a free spot on a running machine: iterate over machines in random order for better spreading
        for m in random.sample(self._machines, machine_count):
            print("looking for container with engine {1} on machine {0}".format(m.id, engine.name))
            container, machine = m.try_do_scan(engine, file_path)
            if container is not None:
                print("found container {0} with engine {2} on machine {1}".format(container.id, machine.id, engine.name))
                break
            
        if container is None:
            # check if we are already starting a machine
            self._machine_lock.writer_lock.acquire()
            if len(self._machines_starting) != 0:
                # iterate over starting machine and check if we can wait for one
                for event, workers_waiting in self._machines_starting.items():
                    if workers_waiting != self.max_containers_per_machine * self.max_scans_per_container:
                        # release lock and wait for machine startup
                        self._machines_starting[event] += 1
                        self._machine_lock.writer_lock.release()
                        event.wait()
                        container, reduce_scan_time_by = self._get_container_for_scan(engine, file_path)
                        reduce_scan_time_by = self.expected_machine_startup_time
                        return container, reduce_scan_time_by
                
            self._machine_lock.writer_lock.release()

            # start a new machine
            m = self._create_machine() # blocks for as long as the machine startup takes
            container, machine = m.try_do_scan(engine, file_path)

        # copy scan to target machine if required
        machine.copy_file_to_machine_tmp_dir(file_path)
                
        return container, reduce_scan_time_by

    def _increase_workforce_if_possible(self):
        with self._worker_lock.writer_lock:
            queue_size = self.pool.get_queue_size_including_active_workers()
            worker_amount = self.pool.get_worker_amount()
            
            if queue_size <= worker_amount:
                print("_increase_workforce_if_possible: queue is still smaller ({0}) than the current worker count ({1})".format(queue_size, worker_amount))
                return

            if worker_amount >= self._max_workers:
                print("_increase_workforce_if_possible: max workers reached {0}".format(self._max_workers))
                return
            
            '''# no machine start requiered, do it => prior to threads = minmachines*engines*scansperengine
            max_scans_per_machine = self.max_containers_per_machine * self.max_scans_per_container
            if max_scans_per_machine % worker_amount != 0:
                print("_increase_workforce_if_possible: creating worker for existing machine")
                self.pool.add_worker()
                return'''
            
            # would require machine start. is it worth it? (calc worst case)
            time_to_finish_current_queue = self._calculate_time_to_finish_queue()
            print("_increase_workforce_if_possible: time to finish queue {0} | queue_size: {1} average_scan_time: {2} worker_amount: {3}".format(time_to_finish_current_queue, queue_size, self._get_average_scan_time(), worker_amount))
            if time_to_finish_current_queue < self.expected_machine_startup_time:
                # finishing the queue is faster than starting a new machine
                print("_increase_workforce_if_possible: finishing queue without starting new machine is faster")
                return
            
            # how many machines should we start?
            amount_of_machines = int(time_to_finish_current_queue/self.expected_machine_startup_time)
            
            for _j in range(0, amount_of_machines):
                # start new machine by adding a worker who will do it pre scan
                print("_increase_workforce_if_possible: creating {0} workers for new machine".format(self.max_containers_per_machine * self.max_scans_per_container))
                for _i in range(0, self.max_containers_per_machine * self.max_scans_per_container):
                    self.pool.add_worker()
    
    def _calculate_time_to_finish_queue(self):
        queue_size = self.pool.get_queue_size_including_active_workers()
        avg_scan_time = self._get_average_scan_time()
        total_workers = self.pool.get_worker_amount()
        
        machines_starting = len(self._machines_starting)

        if machines_starting != 0:
            workers_waiting_for_machine_start = machines_starting * self.max_containers_per_machine * self.max_scans_per_container
            currently_working_workers = total_workers - workers_waiting_for_machine_start

            items_completable_in_machine_startup_time = int(self.expected_machine_startup_time / avg_scan_time) * currently_working_workers
            
            time = self.expected_machine_startup_time
            time += (queue_size - items_completable_in_machine_startup_time) * avg_scan_time / total_workers

            return time
        else:
            return queue_size * avg_scan_time / total_workers


    def scan(self, engine, file_buffer):
        scan_promise = self.pool.add_task(self._scan_internal, engine, file_buffer)

        # increase workforce if required and possible
        self._increase_workforce_if_possible()

        return scan_promise
    
    def get_signature_version(self, engine):
        containers = self._machines[0].find_containers_by_engine(engine)
        
        if len(containers) == 0:
            return "-"
        
        for container in containers:
            if container.is_running():
                return container.get_signature_version()
        
        return "-"

    def check_if_this_engine_is_updated_on_all_machines(self, result, machine_update_promises, update_promise):
        result = json.loads(result)
        engine_name = result["engine"]
        #print("check_if_this_engine_is_updated_on_all_machines: engine {0}".format(engine_name))
        not_pending = True
        failed_promises = 0
        for promise in machine_update_promises[engine_name]:
            not_pending &= promise._state != -1
            if promise._state == 0:
                failed_promises += 1
        
        #print("check_if_this_engine_is_updated_on_all_machines: engine {0}, not_pending: {1}, failed_promises: {2}".format(engine_name, not_pending, failed_promises))
        if not_pending:
            # last one will trigger this
            for engine, value_promise in update_promise._engine_promises.items():
                if engine.name == engine_name:
                    if failed_promises == 0:
                        #print("check_if_this_engine_is_updated_on_all_machines: resolving engine {0}".format(engine_name))
                        value_promise.do_resolve(result)
                    else:
                        #print("check_if_this_engine_is_updated_on_all_machines: rejecting engine {0}".format(engine_name))
                        value_promise.do_reject(Exception("Update of {0} failed on {1} machines".format(engine_name, failed_promises)))
                    return
                    
    def update(self):
        update_promises = dict()

        # create placeholder promises for each engine. is resolved if updated on all machines
        machine_update_promises = dict()
        for engine_class in self.engine_classes:
            engine = engine_class(self.cfg_parser)

            if engine.is_disabled():
                continue
            
            machine_update_promises[engine.name] = []
            update_promises[engine] = Promise(None)
        
        # create update promise
        update_promise = MultiActionPromise(update_promises)

        # call update on each machine
        for machine in self._machines:
            machine_update_promise = machine.update()

            # set callback post update to check if all engines on all machines are updated => if so, triggers resolve on update promise
            for engine, engine_update_promise in machine_update_promise._engine_promises.items():
                machine_update_promises[engine.name].append(engine_update_promise)
                engine_update_promise.then(
                    lambda result: self.check_if_this_engine_is_updated_on_all_machines(result, machine_update_promises, update_promise),
                    lambda result: self.check_if_this_engine_is_updated_on_all_machines(result, machine_update_promises, update_promise),
                )
        
        return update_promise

    def get_statistics(self):
        statistics = {
            "strategy_name": "AutoScaleDockerStrategy",
            "max_scans_per_container": self.max_scans_per_container,
            "worker_threads": self.pool.get_worker_amount(),
            "worker_threads_working": len(self.pool.get_working_workers()),
            "worker_per_machine": self.max_containers_per_machine * self.max_scans_per_container,
            "worker_threads_min": self._min_workers,
            "woerker_threads_max": self._max_workers,
            "machines_active": len(self._machines),
            "machines_starting": len(self._machines_starting),
            "machines_min": self.min_machines,
            "machines_max": self.max_machines,
            "queue_size": self.pool.get_queue_size(),
            "average_scan_time": self._get_average_scan_time(),
            "time_to_finish_queue": self._calculate_time_to_finish_queue(),
            "expected_machine_startup_time": self.expected_machine_startup_time,
            "minimal_machine_run_time": self.minimal_machine_run_time,
            "machines": list(map(lambda machine: {
                machine.id: {
                    "never_shutdown": machine.never_shutdown,
                    "shutdown_check_backoff": machine._shutdown_check_backoff if not machine.never_shutdown else "-",
                    "shutdown_check_last_date": str(machine._shutdown_check_last_date) if not machine.never_shutdown else "-", 
                    "shutdown_check_next_date": str(machine._shutdown_check_last_date + datetime.timedelta(0, machine.minimal_machine_run_time ** machine._shutdown_check_backoff)) if machine._shutdown_check_backoff != None else "-",
                    "container_amount": len(machine.containers), 
                    "containers": list(map(lambda container: {
                        "id": container.id, 
                        "engine": container.engine.name, 
                        "scan_count": len(container.scans)
                        }, machine.containers)) if len(machine.containers) != 0 else "None"
                    }
                }, self._machines))
        }
        return statistics

