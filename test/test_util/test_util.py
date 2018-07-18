import time
import subprocess

time.tzset()

def ts_text(sec, usec = 0):
    """Convert `sec`, `usec` into local time text"""
    tm = time.localtime(sec)
    tz_sec = -time.altzone if tm.tm_isdst else -time.timezone
    tz_hr = tz_sec / 3600
    tz_min = abs((tz_sec % 3600) / 60)
    tz_text = "%+03d:%02d" % (tz_hr, tz_min)
    text = time.strftime("%FT%T", tm) + ( ".%06d" % usec ) + tz_text
    return text

class BalerDaemon(object):
    """Start / stop baler daemon from Python subprocess"""

    def __init__(self, store_path, store_plugin = "bstore_sos",
                       purge_store = False,
                       config_file = None, config_text = None,
                       input_wkr = None, output_wkr = None,
                       queue_depth = None,
                       log_file = None,
                       log_verbosity = "WARN",
                       gdb_port = None):
        if config_file and config_text:
            raise AttributeError("`config_file` and `config_text` "
                                 "cannot be supplied at the same time.")
        self.gdb_port = gdb_port
        self.store_path = store_path
        if purge_store:
            shutil.rmtree(store_path, ignore_errors = True)
        self.proc = None
        self.config_text = config_text
        self.config_file = config_file
        opts =  {
                    '-s': store_path,
                    '-S': store_plugin,
                    '-I': input_wkr,
                    '-O': output_wkr,
                    '-Q': queue_depth,
                    '-l': log_file,
                    '-v': log_verbosity,
                }
        self.opts = { k:v for k,v in opts.iteritems() if v != None }

    def __del__(self):
        self.stop()

    def is_running(self):
        return self.proc and self.proc.returncode == None

    def start(self):
        if self.is_running():
            return
        if self.gdb_port:
            cmd = "exec gdbserver :%d balerd -F" % self.gdb_port
        else:
            cmd = "exec balerd -F"
        for k, v in self.opts.iteritems():
            cmd += (' ' + k + ' ' + v)
        if self.config_file:
            cmd += ' -C ' + self.config_file
        elif self.config_text:
            self.tmp_file = tempfile.NamedTemporaryFile()
            self.tmp_file.write(self.config_text)
            cmd += ' -C ' + self.tmp_file.name
        self.proc = subprocess.Popen(cmd, shell=True, close_fds = True)
        if self.gdb_port:
            raw_input("gdb port: %s ... please attach and press ENTER to continue" % str(self.gdb_port))
        else:
            time.sleep(3) # to make sure that it is fully up

    def stop(self):
        if not self.is_running():
            return
        self.proc.terminate()
        self.proc.wait()
