from promise import Promise

#-----------------------------------------------------------------------
# this is basically a promise for the whole scan and for all subscans. use engine_then to setup the subtask callbacks
class MultiActionPromise(Promise):
    def __init__(self):
        # TODO add engine promises via constructor => potential race
        Promise.__init__(self)
        self.engine_promises = dict()
    
    def _did_all_engine_promises_run(self, res):
        ret = True
        all_fulfilled = True
        for engine, engine_promise in self.engine_promises.items():
            ret &= engine_promise._state != -1
            all_fulfilled &= engine_promise._state == 1
        
        if ret:
            if all_fulfilled:
                self.do_resolve("All done")
            else:
                self.do_reject("Some failed")

    def engine_then(self, did_fulfill=None, did_reject=None):
        for engine, engine_promise in self.engine_promises.items():
            engine_promise.then(did_fulfill, did_reject)
            engine_promise.then(self._did_all_engine_promises_run, self._did_all_engine_promises_run)

        return self
    
    def get_scanning_engines(self):
      return self.engine_promises.keys()