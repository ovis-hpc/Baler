import os
import re
import pdb
import time
import socket
import tempfile
import subprocess

time.tzset()

def ts_text(sec, usec = 0):
    """Convert `sec`, `usec` into local time text"""
    tm = time.localtime(sec)
    tz_sec = -time.altzone if tm.tm_isdst else -time.timezone
    if not tz_sec:
        tz_text = "+00:00"
    else:
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
                       log_verbosity = "INFO",
                       gdb_port = None,
                       log_truncate = True):
        self.rm_log = False
        self.rm_config = False
        if config_file and config_text:
            raise AttributeError("`config_file` and `config_text` "
                                 "cannot be supplied at the same time.")
        self.gdb_port = gdb_port
        self.store_path = store_path
        if purge_store:
            shutil.rmtree(store_path, ignore_errors = True)
        self.proc = None
        if not config_file:
            # create config file from config_text
            (fd, config_file) = tempfile.mkstemp()
            self.rm_config = True
            f = os.fdopen(fd, "w")
            f.write(config_text)
            f.close()
        self.config_text = config_text
        self.config_file = config_file
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
        if self.rm_config:
            os.unlink(self.config_file)

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
        cmd += ' -C ' + self.config_file
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

DICT_PATH = os.path.dirname(__file__) + "/eng-dictionary"

def make_store(store_path, hosts, msgs):
    """Make a store from list of hosts and msgs

    Parameters:

    store_path (str) - the path of the store to be generated

    hosts (list(str)) - list of hosts (or "host host_id" entries)

    msgs (list(str)) - list of raw messages to be sent (via socket) to balerd

    """
    host_path = None
    global DICT_PATH
    try:
        (host_fd, host_path) = tempfile.mkstemp()
        with os.fdopen(host_fd, "w") as hf:
            for h in hosts:
                print >>hf, h
        config_text = """
            tokens type=HOSTNAME path=%(host_path)s
            tokens type=WORD path=%(dict_path)s
            plugin name=bout_store_msg
            plugin name=bout_store_hist tkn=1 ptn=1 ptn_tkn=1
            plugin name=bin_tcp port=10514 parser=syslog_parser
        """ % {
            "host_path": host_path,
            "dict_path": DICT_PATH,
        }
        balerd = BalerDaemon(store_path, config_text = config_text)
        balerd.start()
        try:
            sock = socket.create_connection(("localhost", 10514))
        except:
            pdb.set_trace()
        for m in msgs:
            sock.send(m)
        sock.close()
        balerd.wait_idle()
        balerd.stop()
    finally:
        if host_path:
            os.unlink(host_path)
