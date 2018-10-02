import os
import re
import time
import tempfile
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

def proc_pid_ustime(pid):
    f = open('/proc/%d/stat' % pid, 'r')
    rec = f.readline().split(' ')
    return map(int, rec[13:15])

class BalerDaemon(object):
    """Start / stop baler daemon from Python subprocess"""

    def __init__(self, store_path, store_plugin = "bstore_sos",
                       purge_store = False,
                       config_file = None, config_text = None,
                       input_wkr = None, output_wkr = None,
                       queue_depth = None,
                       log_file = None,
                       log_verbosity = "WARN",
                       gdb_port = None,
                       log_truncate = True):
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
        self.rm_log = False
        if not log_file:
            # If not log_file given, use tmpfile
            (fd, log_file) = tempfile.mkstemp()
            self.rm_log = True
            os.close(fd)
        if log_truncate:
            f = open(log_file, "w")
            f.close()
        else:
            f = open(log_file, "a")
            f.close()
        self.log_file = log_file
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
        if self.rm_log:
            os.unlink(self.log_file)

    def is_running(self):
        return self.proc and self.proc.returncode == None

    def _wait_ready(self):
        pos = 0
        ready_re = re.compile(".* Baler is ready..*")
        is_ready = False
        while True:
            x = self.proc.poll()
            if self.proc.returncode != None:
                # balerd terminated
                break
            blog = open(self.log_file, "r")
            blog.seek(pos, 0)
            ln = blog.readline()
            if not ln:
                pos = blog.tell()
                blog.close()
                time.sleep(0.1)
                continue
            m = ready_re.match(ln)
            if m:
                is_ready = True
                blog.close()
                break
            pos = blog.tell()
            blog.close()
        if not is_ready:
            raise Exception("Something bad happened to balerd")

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
        self._wait_ready()

    def stop(self):
        if not self.is_running():
            return
        self.proc.terminate()
        self.proc.wait()

    def wait_idle(self, interval = 3.0):
        """Blocking wait until `balerd` is not busy"""
        pid = self.proc.pid
        a = None
        b = proc_pid_ustime(pid)
        while a != b:
            a = b
            time.sleep(interval)
            b = proc_pid_ustime(pid)
