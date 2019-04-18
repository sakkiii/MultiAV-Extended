import time
import uuid

from sys import exc_info
from threading import Thread
from multiprocessing import Process, Queue
from promise import Promise

# These are the potential states of a promise
STATE_PENDING = -1
STATE_REJECTED = 0
STATE_FULFILLED = 1

def _process_function(queue, executor):
    def resolve(value):
        # type: (T) -> None
        #print("resolve called")
        queue.put(STATE_FULFILLED)
        queue.put(value)

    def reject(reason, traceback=None):
        # type: (Exception, TracebackType) -> None
        #print("reject called")
        queue.put(STATE_REJECTED)
        queue.put(reason)
        if traceback is not None:
            queue.put(traceback)
    
    #print("_process_function calling executor")
    try:
        executor(resolve, reject)
    except Exception as e:
        reject(e)
    #print("_process_function executor finished")


# starts the executor function non blocking in a seperate thread
class ParallelPromise(Promise):
    def __init__(self, executor=None, scheduler=None):
        Promise.__init__(self, executor, scheduler)

    def wait(self, timeout=None):
        while self._state == STATE_PENDING:
            time.sleep(0.1)

    def _resolve_from_executor(self, executor):
        # type: (Callable[[Callable[[T], None], Callable[[Exception], None]], None]) -> None
        # self._capture_stacktrace()
        synchronous = True
        error = None
        traceback = None

        def thread_process_wrapper(process, queue):
            #print("thread_process_wrapper")
            try:
                process.join()
                process.terminate()
                new_state = int(queue.get())
                #print("new_state: {0}".format(new_state))
                res = queue.get()
                #print("res: {0}".format(res))

                if new_state == STATE_FULFILLED:
                    self._resolve_callback(res)
                else:
                    traceback = queue.get() if queue.qsize() != 0 else None
                    self._reject_callback(Exception(res), synchronous, traceback)
                #print("thread_process_wrapper finished")
            except Exception as e:
                #print("thread_process_wrapper Exception: {0}".format(e))
                self._reject_callback(e, synchronous, traceback)
            return

        try:
            #print("starting process")
            queue = Queue()
            process = Process(target=_process_function, args=(queue, executor))
            process.start()
            #print("starting wait for result thread")
            self.thread = Thread(target=thread_process_wrapper, args=(process,queue))
            self.thread.daemon = True
            self.thread.start()
        except Exception as e:
            traceback = exc_info()[2]
            error = e
            print("prallel promise exception: {0}".format(e))

        synchronous = False

        if error is not None:
            self._reject_callback(error, True, traceback)