import threading
import json
import sys

from threading import Lock
from promise import Promise

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    from Queue import Queue
else:
    from queue import Queue

class PluginExecutorPool:
    def __init__(self, num_threads, workers_maxsize = 0):
        self.workers_maxsize = workers_maxsize
        self.tasks = Queue()
        self.min_threads = num_threads
        self.workers = []

        self._worker_lock = Lock()
        self._tasks_lock = Lock()

        with self._worker_lock:
            for _ in range(num_threads):
                self.workers.append(Worker(self.tasks))
    
    def _find_workers_to_remove(self):
        with self._worker_lock:
            with self._tasks_lock:
                queue_size= self.get_queue_size()
                if queue_size >= self.get_worker_amount():
                    return []
                        
                idle_workers = list(filter(lambda w: not w.working, self.workers))
                total_idle_workers = len(idle_workers)
                max_removalble_workers = self.get_worker_amount() - self.min_threads

                if total_idle_workers <= max_removalble_workers:
                    return idle_workers[:total_idle_workers]

                return idle_workers[:max_removalble_workers]

    def add_worker(self, amount=1):
        if amount <= 0:
            return
        
        if self.workers_maxsize <= 0:
            return

        with self._worker_lock:
            amount = amount if len(self.workers) + amount <= self.workers_maxsize else self.workers_maxsize - len(self.workers)
        
            for _ in range(amount):
                self.workers.append(Worker(self.tasks))
        
        print("created {0} new worker(s)".format(amount))

    def remove_worker(self, workers):
        if self.workers_maxsize <= 1:
            return

        if len(workers) <= 0:
            return

        with self._worker_lock:
            for worker in workers:
                worker.mark_for_removal()
                self.workers.remove(worker)
        
        print("marked {0} worker(s) for removal".format(len(workers)))

    def get_queue_size(self):
        with self._tasks_lock:
            return self.tasks.qsize()

    def get_worker_amount(self):
        with self._worker_lock:
            return len(self.workers)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        with self._tasks_lock:
            print("adding task to queue")
            p = Promise(lambda resolve, reject: self.tasks.put((resolve, reject, func, args, kargs)))

        # set a post task
        p.then(
            lambda res: self.remove_worker(self._find_workers_to_remove()),
            lambda res: self.remove_worker(self._find_workers_to_remove())
        )
        return p

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        promises = []
        for args in args_list:
            promises.append(self.add_task(func, args))

        return promises

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()


class Worker(threading.Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks):
        threading.Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self._lock = Lock()
        self.working = False
        self.marked_for_removal = False
        self.start()

    def run(self):
        while True:            
            try:
                resolve, reject, func, args, kargs = self.tasks.get(False, 1)

                with self._lock:
                    self.working = True

                try:
                    # run task and resolve with return value
                    # will execute the function doing the http request. it's therefor usable for all plugins
                    res = func(*args, **kargs)
                    resolve(json.dumps(res))            
                except Exception as e:
                    # reject promise with exception
                    reject(e)

                finally:
                    with self._lock:
                        self.working = False
                    
                    # Mark this task as done, whether the promise is rejected or resolved
                    self.tasks.task_done()
            except Exception as e:
                # get timeout
                pass
            finally:
                with self._lock:
                    if self.marked_for_removal:
                        print("stopping thread as marked for removal")
                        return

    def mark_for_removal(self):
        with self._lock:
            self.marked_for_removal = True
    
    def is_working(self):
        with self._lock:
            return self.mark_for_removal
