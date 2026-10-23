"""ABBA CPU cost of real Unix HTTP/StageLog/CursorStore, not proxy throughput."""
import argparse
import copy
import http.server
import importlib.util
import json
import multiprocessing as mp
import socketserver
import statistics
import tempfile
import time
from pathlib import Path


def serve(path, template, current, modern, ready, stop):
    class Server(socketserver.UnixStreamServer): pass
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        def log_message(self, *_): pass
        def do_GET(self):
            sequence = current.value
            value = copy.deepcopy(template)
            value['sequence'] = value['snapshot']['sequence'] = sequence
            value['age_ms'] = 1000
            raw = json.dumps(value, separators=(',', ':')).encode()
            self.send_response(200)
            if modern:
                self.send_header('X-PCS-Stage-History', '1')
                if '/history?' in self.path:
                    self.send_header('X-PCS-Stage-Oldest', str(max(1, sequence-2)))
                    self.send_header('X-PCS-Stage-Latest', str(sequence))
                    self.send_header('X-PCS-Stage-Latest-Age-Ms', '1000')
                    self.send_header('X-PCS-Stage-Gap', 'none')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    with Server(path, Handler) as server:
        server.timeout = .05
        ready.set()
        while not stop.is_set(): server.handle_request()


def measure(module, template, modern, count):
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d)/'server.sock')
        current, ready, stop = mp.Value('Q', 1), mp.Event(), mp.Event()
        process = mp.Process(target=serve, args=(path, template, current, modern, ready, stop))
        process.start()
        try:
            if not ready.wait(3): raise RuntimeError('owned fixture server did not start')
            clock = [0.0]
            reader = module.StageReader(path, b'synthetic-cost-key', Path(d)/'cursor', enabled=True, clock=lambda: clock[0])
            writer = module.StageLog(d)
            durations = []
            for i in range(count+4):
                current.value, clock[0] = i+1, i*10.0
                before = time.process_time_ns()
                result = module.collect_regular_stage(reader, writer, 'synthetic-cost-scope', regular_tick=clock[0], next_regular=clock[0]+10)
                cpu = time.process_time_ns()-before
                if result['output_status'] != 'written' or result['checkpoint_status'] != 'saved':
                    raise RuntimeError('cost fixture dropped output/cursor')
                if i >= 4: durations.append(cpu)
            checkpoint, status = reader.store.load()
            if status != 'loaded' or checkpoint['sequence'] != count+4: raise RuntimeError('cost checkpoint mismatch')
            return {'cpu_ns_per_cycle':durations,'median_cpu_ns':statistics.median(durations),
                    'iterations':count,'server_cpu_excluded':True,'legacy_or_history':'history_latest_no_backlog' if modern else 'legacy'}
        finally:
            stop.set(); process.join(3)
            if process.is_alive(): process.kill(); process.join(3)
            if process.is_alive(): raise RuntimeError('owned fixture process not reaped')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('baseline'); p.add_argument('candidate'); p.add_argument('fixture'); p.add_argument('output')
    args = p.parse_args()
    def load(path, name):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module
    modules = {'A':load(args.baseline,'baseline_stage'), 'B':load(args.candidate,'candidate_stage')}
    template = json.loads(Path(args.fixture).read_text())
    rounds = [{'arm':arm,**measure(modules[arm],template,arm=='B',24)} for arm in 'ABBA']
    a = statistics.median(r['median_cpu_ns'] for r in rounds if r['arm']=='A')
    b = statistics.median(r['median_cpu_ns'] for r in rounds if r['arm']=='B')
    out = {'scope':'ordinary latest publication, real private Unix HTTP and actual fsync/cursor; not whole-proxy throughput',
           'order':'ABBA','rounds':rounds,'baseline_cpu_median_ns':a,'candidate_cpu_median_ns':b,'ratio':b/a,
           'gate':'PASS' if b/a <= 1.10 else 'HOLD_CPU_REGRESSION','threshold_ratio':1.10}
    Path(args.output).write_text(json.dumps(out,indent=2)+'\n')
    if out['gate'] != 'PASS': raise RuntimeError('consumer CPU cost gate failed')


if __name__ == '__main__': main()
