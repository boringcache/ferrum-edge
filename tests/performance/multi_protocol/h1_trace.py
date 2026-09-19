"""Hosted-only H1 passive supervisor. Never launches a gateway or a benchmark.

Only the synthetic fixture and fixed observer/perf inventory are executable here.
The ordinary harness owns gateway/client creation, work, and shutdown.
"""
import argparse
import ctypes
import hashlib
import functools
import json
import math
import os
from pathlib import Path
import platform
import resource
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

from process_usage import capture, parse_stat
from transport_diagnostics import parse_diag
from h1_trace_contract import (BOUNDS, LOSSES, SYSCALLS, COUNTERS, validate_record,
                               syscall_coverage, fd_lifetimes, decode_cpu, clock_receipt_window)
# The shared hosted artifact scrubber's sibling import is scoped explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent / 'h3_proof'))
from hosted import scrub

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STAGE = Path('/tmp/ferrum-h1-trace')
TICKS = os.sysconf('SC_CLK_TCK')
PAGE = os.sysconf('SC_PAGE_SIZE')
PARENTS = dict(h1='ac7ff645f766597b9e4f38aa9e18272c0b3c249d',
               h3='45dbde8ccc9575b225890afb450579213d62cb21')


def write(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_metadata(path, limit=256 * 1024):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(limit + 1)
        return dict(text=data[:limit].decode(errors='replace'), truncated=len(data) > limit)
    except OSError as error:
        return dict(errno=error.errno)


def clock():
    before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    unix = time.time_ns()
    return dict(before_ns=before, unix_ns=unix,
                after_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))


def clock_receipt():
    """Timestamp receipt in this producer's actual boot and time namespace."""
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    namespace = Path('/proc/self/ns/time').stat().st_ino
    return dict(clock(), kind='clock_receipt', clock='CLOCK_MONOTONIC',
                boot_id=boot, time_namespace=namespace)


def write_binding(output, *, runtime, config, sample, arm, pair, payload, raw_sample, client_exit):
    """Fixed data-only runner command; future client artifacts need not exist yet."""
    paths = dict(runtime=runtime, config=config, sample=sample,
                 raw_sample=raw_sample, client_exit=client_exit)
    if (arm not in ('ferrum', 'ferrum-baseline', 'ferrum-exp-cutoff-one')
            or type(pair) is not int or not 1 <= pair <= 4
            or type(payload) is not int or payload not in (10240, 71680, 512000, 1048576, 5242880)):
        raise ValueError('invalid H1 trace binding selection')
    for path in (output, *paths.values()):
        if not Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError('H1 trace binding requires absolute artifact paths')
    destination = Path(output) / 'bind.json'
    if destination.exists():
        raise ValueError('H1 trace binding already exists')
    write(destination, dict(paths, arm=arm, pair=pair, payload=payload))


def identity(pid):
    proc = Path('/proc') / str(pid)
    state = parse_stat((proc / 'stat').read_text(), TICKS, PAGE)
    cgroup = (proc / 'cgroup').read_text().strip().split('0::', 1)[1]
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    row = dict(pid=pid, start_ticks=state['start_ticks'], ticks=TICKS,
               cgroup=cgroup, cgroup_id=(Path('/sys/fs/cgroup') / cgroup.lstrip('/')).stat().st_ino,
               executable=os.readlink(proc / 'exe'), executable_sha256=digest(proc / 'exe'),
               boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               namespaces={name: (proc / 'ns' / name).stat().st_ino for name in ('pid', 'mnt', 'net', 'time', 'user')},
               privileges={key: status.get(key, '').strip() for key in ('Uid', 'Gid', 'CapEff', 'CapPrm', 'CapAmb', 'NoNewPrivs', 'Seccomp')},
               clock=clock(), threads=[])
    tasks = sorted((proc / 'task').iterdir())
    if len(tasks) > BOUNDS['threads']:
        raise ValueError('thread inventory bound')
    for task in tasks:
        try:
            row['threads'].append(dict(tid=int(task.name), **parse_stat((task / 'stat').read_text(), TICKS, PAGE)))
        except FileNotFoundError:
            row.setdefault('thread_races', []).append(int(task.name))
    return row


def same_generation(before, after):
    return all(before.get(k) == after.get(k) for k in ('pid', 'start_ticks', 'cgroup_id', 'executable_sha256', 'boot_id', 'namespaces'))


def target_alive(owner):
    try:
        raw = Path(f'/proc/{owner["pid"]}/stat').read_text()
    except FileNotFoundError:
        return False
    if parse_stat(raw, TICKS, PAGE)['start_ticks'] != owner['start_ticks']:
        raise RuntimeError('gateway PID generation changed')
    return raw[raw.rfind(')') + 2:].split()[0] not in ('Z', 'X', 'x')


def completion_evidence(binding):
    """Read retained client output, never infer drain from elapsed wall time.

    H1 prints this report only after Phases::finish joins all request workers.
    Aborted/timed-out drains cannot authorize teardown, even with exit code 0.
    Useful-work validity remains the independent benchmark validity contract.
    """
    paths = {key: Path(binding[key]) for key in ('sample', 'raw_sample', 'client_exit')}
    data = {key: path.read_bytes() for key, path in paths.items()}
    if data['client_exit'].strip() != b'0':
        raise ValueError('client exit failed/missing before teardown')
    sample, raw = (json.loads(data[key]) for key in ('sample', 'raw_sample'))
    phases = raw['phases']
    if (not isinstance(phases, dict) or sample['phases'] != phases or
            phases.get('timed_out') is not False or phases.get('stalled_workers') != [] or
            phases.get('transport_close_timed_out') is not False):
        raise ValueError('client request drain incomplete')
    for key in ('measurement_secs', 'measurement_elapsed_secs', 'drain_secs', 'drain_start_monotonic_secs'):
        value = phases.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('missing/invalid client drain phase: ' + key)
    if not 0 < phases['measurement_secs'] <= phases['measurement_elapsed_secs']:
        raise ValueError('client measurement incomplete before drain')
    if (sample.get('gateway') != binding['arm'] or sample.get('pair') != binding['pair'] or
            sample.get('payload_size') != binding['payload']):
        raise ValueError('client completion binding mismatch')
    return dict(files={key: dict(path=str(paths[key]), sha256=hashlib.sha256(value).hexdigest())
                       for key, value in data.items()}, phases=phases)


class CaptureLifecycle:
    """Runner requests closure; only this live supervisor authorizes teardown."""
    def __init__(self, out, owner, binding, ready, collectors):
        self.out, self.owner, self.binding, self.ready = out, owner, binding, ready
        self.collectors = {name: c for name, c in collectors.items()
                           if c and c.ready.get('status') == 'supported'}
        self.teardown = None
        self.observations = {}
        self.target_gone = None

    def poll(self):
        before = clock()
        alive = target_alive(self.owner)
        if not alive:
            if self.teardown is None:
                raise RuntimeError('gateway exited before verified workload closure')
            if self.target_gone is None:
                self.target_gone = dict(observed_at=clock(), exact_exit_ns=None)
        for name, collector in self.collectors.items():
            row = self.observations.setdefault(name, {})
            status = collector.process.poll()
            after = clock()
            if status is None:
                row['last_alive'] = before
            else:
                row.setdefault('exit', dict(returncode=status, observed_at=after,
                    bounds_ns=[row.get('last_alive', before)['before_ns'], after['after_ns']],
                    exact_exit_ns=None))
                # The target can die between the initial /proc read and poll.
                if name == 'cpu' and status == 0 and self.teardown is not None and alive:
                    alive = target_alive(self.owner)
                    if not alive and self.target_gone is None:
                        self.target_gone = dict(observed_at=clock(), exact_exit_ns=None)
                if name != 'cpu' or status != 0 or self.teardown is None or alive:
                    raise RuntimeError('collector exited before workload closure or outside verified target teardown')
                row['exit']['expected_target_teardown'] = True
        return alive

    def authorize_teardown(self):
        if self.teardown is not None or not (self.out / 'teardown-request.json').exists():
            return
        request = json.loads((self.out / 'teardown-request.json').read_text())
        now = clock()
        if not isinstance(request, dict) or not isinstance(request.get('at'), dict):
            raise ValueError('stale/mismatched teardown request')
        at = request['at']
        if (request.get('session') != self.ready['session'] or
                request.get('binding_sha256') != self.ready['binding_sha256'] or
                request.get('owner') != self.owner or
                digest(self.out / 'bind.json') != self.ready['binding_sha256'] or
                not all(type(at.get(k)) is int for k in ('before_ns', 'after_ns', 'unix_ns')) or
                not self.ready['at']['after_ns'] <= at['before_ns'] <= at['after_ns'] <= now['before_ns']):
            raise ValueError('stale/mismatched teardown request')
        evidence = completion_evidence(self.binding)
        if request.get('evidence') != evidence:
            raise ValueError('client completion changed after retention')
        window = clock_receipt_window(evidence['phases'], [self.ready['at'], at],
            boot_id=self.owner['boot_id'], time_namespace=self.owner['namespaces']['time'])
        if not window.get('valid'):
            raise ValueError('completion does not bracket this capture measurement')
        self.acknowledge_teardown(request, dict(kind='retained_client_report', measurement=window))

    def acknowledge_teardown(self, request, completion):
        """Live transition shared with the hosted fixture's joined-work receipt."""
        if self.teardown is not None:
            raise RuntimeError('duplicate teardown transition')
        current = identity(self.owner['pid'])
        if not same_generation(self.owner, current):
            raise RuntimeError('gateway generation changed before teardown')
        # Poll AFTER reads: a queued marker must never forgive an already-dead
        # collector/target. No teardown state is installed until both are live.
        self.poll()
        self.teardown = dict(session=self.ready['session'], binding_sha256=self.ready['binding_sha256'],
            owner=current, request=request, at=clock(), phase='verified_teardown', completion=completion,
            collector_observations=json.loads(json.dumps(self.observations)))
        write(self.out / 'teardown-ready.json', self.teardown)

    def coverage_end(self, fallback):
        # Conservative lower bound on collector end, never supervisor/decode end.
        return min([fallback] + [r['last_alive']['before_ns'] for r in self.observations.values()
                                  if 'last_alive' in r])

    def usage(self):
        values = []
        for name, collector in self.collectors.items():
            if collector.process.poll() is not None:
                continue
            value = capture(collector.process.pid, TICKS, PAGE)
            if value is None:
                # perf can exit between poll and /proc read during removal.
                # Recheck the strict lifecycle; never forgive a live read failure.
                self.poll()
                if name != 'cpu' or collector.process.poll() is None:
                    raise RuntimeError('observer resource capture missing')
                self.observations[name]['resource_read_exit_race'] = dict(at=clock(), usage_unknown=True)
            else:
                values.append(value)
        return values

    def verify_stop(self):
        if self.teardown is None:
            raise RuntimeError('stop without verified client completion and request drain')
        if self.target_gone is None:
            raise RuntimeError('stop before owned gateway removal')
        if (digest(self.out / 'bind.json') != self.ready['binding_sha256'] or
                completion_evidence(self.binding) != self.teardown['request']['evidence']):
            raise ValueError('client completion/binding changed during teardown')

    def reaped(self, name, status):
        row = self.observations.setdefault(name, {})
        at = clock()
        row['reaped_at'] = at
        row.setdefault('exit', dict(returncode=status['returncode'], observed_at=at,
            bounds_ns=[row.get('last_alive', self.ready['at'])['before_ns'], at['after_ns']],
            exact_exit_ns=None, supervisor_stop=True))

    def report(self):
        return dict(teardown=self.teardown, collectors=self.observations, target_gone=self.target_gone,
                    exact_collector_end=False, gateway_removal_fully_observed=False,
                    limits='poll bounds, not exact exit clocks; no samples promised after target exit')


def request_teardown(out):
    """Unprivileged runner call only after client return, retention and stamping."""
    out = Path(out)
    ready = json.loads((out / 'ready.json').read_text())
    binding = json.loads((out / 'bind.json').read_text())
    request = dict(session=ready['session'], binding_sha256=digest(out / 'bind.json'),
                   owner=ready['owner'], evidence=completion_evidence(binding), at=clock_receipt())
    if (out / 'teardown-request.json').exists() or (out / 'teardown-ready.json').exists():
        raise ValueError('teardown handshake already exists')
    write(out / 'teardown-request.json', request)
    # Existing readiness wait budget, also capped by the original capture deadline.
    deadline = min(time.monotonic() + 30, ready['deadline_monotonic'])
    while time.monotonic() < deadline:
        if (out / 'stopped.json').exists():
            raise RuntimeError('supervisor stopped before teardown acknowledgement')
        if (out / 'teardown-ready.json').exists():
            ack = json.loads((out / 'teardown-ready.json').read_text())
            if ack.get('session') != ready['session'] or ack.get('request') != request:
                raise ValueError('stale teardown acknowledgement')
            return
        time.sleep(0.05)
    raise RuntimeError('teardown acknowledgement deadline')


def admit(row):
    p = row['privileges']
    if TICKS != 100 or any(int(x) == 0 for x in p['Uid'].split()) or any(int(p[k], 16) for k in ('CapEff', 'CapPrm', 'CapAmb')):
        raise ValueError('target must be native amd64 ordinary UID with no capabilities')
    if row['namespaces']['time'] != Path('/proc/self/ns/time').stat().st_ino:
        raise ValueError('target/observer time namespace mismatch')


def child_limits(file_limit=BOUNDS["raw_perf_bytes"]):
    # Only owned children; PDEATHSIG closes events even if this supervisor dies.
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent:
        os._exit(125)


def launch(action, *, stdout, stderr, stdin=None, file_limit=BOUNDS["raw_perf_bytes"], **data):
    allowed = {'netns', 'capacity', 'fault', 'denied', 'mode', 'pid', 'out', 'symfs', 'elf'}
    if data.keys() - allowed or not 4096 <= file_limit <= BOUNDS['raw_perf_bytes']:
        raise ValueError('unknown command data/resource bound')
    env = {key: os.environ[key] for key in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
           'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion') if key in os.environ}
    env.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C.UTF-8', HOME='/nonexistent',
               H1_TRACE_ACTION=action, PERF_BUILDID_DIR=str(STAGE / 'buildid-cache'))
    env.update({f'H1_TRACE_{k.upper()}': str(v) for k, v in data.items()})
    return subprocess.Popen(['bash', 'tests/performance/multi_protocol/h1_trace_commands.sh'],
                            cwd=ROOT, env=env, stdin=stdin, stdout=stdout, stderr=stderr,
                            start_new_session=True, preexec_fn=functools.partial(child_limits, file_limit))


def reap(process, command=None):
    if process.poll() is None:
        try:
            if command and process.stdin:
                process.stdin.write(command); process.stdin.flush()
            else:
                os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            return dict(returncode=process.returncode, forced=True)
    return dict(returncode=process.returncode, forced=False)


def command(action, destination, *, limit=2 * 1024**2, timeout=30, **data):
    """Bound each literal metadata command while it runs, not after completion."""
    out = Path(destination)
    errors = out.with_suffix(out.suffix + '.stderr')
    with out.open('wb') as stream, errors.open('wb') as err:
        process = launch(action, stdout=stream, stderr=err, **data)
        deadline = time.monotonic() + timeout
        stopped = None
        while process.poll() is None:
            if time.monotonic() >= deadline or out.stat().st_size + errors.stat().st_size > limit:
                stopped = 'deadline_or_output_cap'; break
            time.sleep(0.02)
        status = reap(process) if stopped else dict(returncode=process.wait(), forced=False)
    status.update(action=action, incomplete=stopped, stdout_sha256=digest(out), stderr_sha256=digest(errors))
    write(out.with_suffix(out.suffix + '.status.json'), status)
    return status


def tcp_inventory(pid):
    """Prime TCP cookies in the actual socket namespace using INET_DIAG.

    The inode/FD inventory is only a bracketed initial observation. It NEVER
    assigns a cookie/role to a syscall or bridges descriptor reuse.
    """
    before = clock()
    proc = Path('/proc') / str(pid)
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open(proc / 'ns/net', os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    rows, fds, errors = [], [], []
    try:
        if os.fstat(original).st_ino != os.fstat(target).st_ino and libc.setns(target, 0):
            raise OSError(ctypes.get_errno(), 'setns')
        deadline = time.monotonic() + 0.5
        for family in (socket.AF_INET, socket.AF_INET6):
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as netlink:
                netlink.settimeout(0.2)
                request = struct.pack('=BBBBI', family, socket.IPPROTO_TCP, 1 << 6, 0, 0xFFFFFFFF)
                request += bytes(40) + struct.pack('=II', 0xFFFFFFFF, 0xFFFFFFFF)
                netlink.sendto(struct.pack('=IHHII', 16 + len(request), 20, 0x301, 1, 0) + request, (0, 0))
                done = False
                while not done:
                    if time.monotonic() > deadline or len(rows) >= 8192:
                        raise ValueError('TCP diag deadline/row cap')
                    data, _, flags, _ = netlink.recvmsg(1024 * 1024)
                    if flags & socket.MSG_TRUNC:
                        raise ValueError('truncated TCP diag')
                    offset = 0
                    while offset + 16 <= len(data):
                        length, kind, flags, seq, _ = struct.unpack_from('=IHHII', data, offset)
                        if length < 16 or offset + length > len(data) or seq != 1 or flags & 0x10:
                            raise ValueError('invalid/interrupted TCP diag')
                        payload = data[offset + 16:offset + length]
                        if kind == 3:
                            done = True
                        elif kind == 2:
                            raise ValueError('TCP diag error ' + str(struct.unpack_from('=i', payload)[0]))
                        elif kind == 20:
                            rows.append(dict(parse_diag(payload), state=payload[1]))
                        offset += (length + 3) & ~3
        paths = list((proc / 'fd').iterdir())
        if len(paths) > BOUNDS['fd_rows_per_snapshot']:
            raise ValueError('FD inventory bound')
        for path in paths:
            try:
                link = os.readlink(path)
                if link.startswith('socket:['):
                    fds.append(dict(fd=int(path.name), inode=int(link[8:-1])))
            except FileNotFoundError:
                errors.append('fd_close_race')
    except (OSError, ValueError) as error:
        errors.append(type(error).__name__ + ':' + str(error))
    finally:
        if libc.setns(original, 0):
            raise OSError(ctypes.get_errno(), 'restore_netns')
        os.close(original); os.close(target)
    inodes = {row['inode'] for row in fds}
    return dict(clock=before, end_clock=clock(), fds=fds,
                sockets=[r for r in rows if r['inode'] in inodes], errors=errors,
                joins_authoritative=False, zero_transient_close_races='unknown; never backfilled')


def retain_dsos(pid, destination):
    """Bounded, read-only mapped ELF metadata, never stack/env/payload scraping."""
    destination.mkdir(parents=True, exist_ok=True)
    raw = read_metadata(f'/proc/{pid}/maps')
    if raw.get('truncated') or 'text' not in raw:
        return dict(complete=False, issue='maps unavailable/oversize', raw=raw)
    records, errors = [], []
    paths = set()
    for line in raw['text'].splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or 'x' not in fields[1]:
            continue
        path = fields[5]
        if not path.startswith('/') or path.endswith(' (deleted)'):
            errors.append('anonymous/deleted executable mapping: ' + path); continue
        paths.add(path)
    if len(paths) > 128:
        return dict(complete=False, issue='DSO count bound')
    total = 0
    metadata_deadline = time.monotonic() + 30
    for path in sorted(paths):
        if time.monotonic() >= metadata_deadline:
            errors.append("DSO metadata deadline"); break
        if '..' in Path(path).parts:
            errors.append('invalid mapping path'); continue
        source = Path(f'/proc/{pid}/root') / path.lstrip('/')
        try:
            size = source.stat().st_size
            total += size
            if total > 512 * 1024**2:
                errors.append('retained ELF package cap'); break
            with source.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    errors.append('executable mapping is not ELF'); continue
            target = destination / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                with source.open('rb') as src, target.open('xb') as dst:
                    while chunk := src.read(1024 * 1024):
                        dst.write(chunk)
            sha = digest(source)
            if sha != digest(target):
                errors.append('DSO changed during copy')
            metadata = target.with_name(target.name + '.elf.txt')
            status = command('elf', metadata, elf=target, timeout=max(0.1, min(5, metadata_deadline - time.monotonic())))
            text = metadata.read_text(errors='replace')
            records.append(dict(path=path, sha256=sha, build_id_lines=[l.strip() for l in text.splitlines() if 'Build ID:' in l],
                                eh_frame='.eh_frame' in text, debug_frame='.debug_frame' in text,
                                decoder=status))
        except OSError as error:
            errors.append(f'{path}:errno={error.errno}')
    return dict(complete=not errors, errors=errors, mappings=raw, dsos=records,
                retained_package_bytes=total, source='target mount namespace, never host libc substitution')


class Observer:
    def __init__(self, out, *, capacity='8192', fault='normal', denied='false'):
        self.out = out
        self.raw = (out / 'syscalls.jsonl').open('wb')
        self.err = (out / 'loader.stderr').open('wb')
        self.process = launch('observer', stdout=self.raw, stderr=self.err, stdin=subprocess.PIPE,
                              netns=Path('/proc/self/ns/net').stat().st_ino,
                              capacity=capacity, fault=fault, denied=denied)
        self.offset = 0
        self.pending = b''
        self.rows = []
        try:
            self.ready = self.wait_for('ready')
        except BaseException:
            self.finish(); raise

    def poll(self):
        with (self.out / 'syscalls.jsonl').open('rb') as stream:
            stream.seek(self.offset)
            data = stream.read(8 * 1024**2)
            self.offset += len(data)
        self.pending += data
        if len(self.pending) > 12 * 1024**2:
            raise ValueError('observer line cap')
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            row = validate_record(json.loads(line))
            if row['phase'] in ('checkpoint', 'snapshot', 'final'):
                role_totals = {}
                for entry in row['rows']:
                    totals = role_totals.setdefault(str(entry['role']), {k: 0 for k in COUNTERS})
                    for key in COUNTERS:
                        totals[key] += entry[key]
                row['role_totals'] = role_totals
            if row['phase'] in ('checkpoint', 'snapshot'):
                row = dict(row, rows=[])  # full rows retained on disk; bounded consumer state
            self.rows.append(row)
            if len(self.rows) > 8260:
                raise ValueError('observer record cap')

    def wait_for(self, phase):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.poll()
            result = next((r for r in self.rows if r['phase'] == phase), None)
            if result:
                return result
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError('observer missing ' + phase)

    def bind(self, owner):
        self.process.stdin.write(('b %d %d %d %d %d\n' % (owner['pid'], owner['start_ticks'], TICKS,
                                  owner['cgroup_id'], owner['namespaces']['net'])).encode())
        self.process.stdin.flush()
        return self.wait_for('bound')

    def finish(self):
        status = reap(self.process, b'q')
        try:
            self.poll()
        except (OSError, ValueError, KeyError, TypeError) as error:
            status['parse_error'] = str(error)
        finally:
            self.raw.close(); self.err.close()
        # Match the H3 retained-verifier redaction: no raw kernel addresses.
        path = self.out / 'loader.stderr'
        path.write_text(scrub(path.read_text(errors='replace')))
        status['partial_record'] = bool(self.pending) or 'parse_error' in status
        return status


class CPU:
    def __init__(self, out, owner, *, file_limit=BOUNDS["raw_perf_bytes"]):
        self.out = out
        for name in ('perf.control', 'perf.ack'):
            os.mkfifo(out / name, 0o600)
        self.control = os.open(out / 'perf.control', os.O_RDWR | os.O_NONBLOCK)
        self.ack = os.open(out / 'perf.ack', os.O_RDWR | os.O_NONBLOCK)
        self.err = (out / 'perf.stderr').open('wb')
        self.process = launch('perf-record', stdout=subprocess.DEVNULL, stderr=self.err,
                              pid=owner['pid'], out=out, file_limit=file_limit)
        self.ready = None
        try:
            os.write(self.control, b'enable\n')
            deadline = time.monotonic() + 10
            receipt = b''
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    receipt += os.read(self.ack, 1024)
                except BlockingIOError:
                    pass
                if b'ack' in receipt:
                    self.ready = dict(status='supported', at=clock(), control_ack=receipt.decode(),
                                      event='cpu-clock:uS', frequency=99, stack_dump=8192, sample_read_enabled_running=True)
                    break
                time.sleep(0.02)
            if self.ready is None:
                self.ready = dict(status='unsupported', reason='no perf enable acknowledgement', at=clock())
                self.finish()
        except BaseException:
            self.finish(); raise

    def finish(self):
        status = reap(self.process)
        self.err.close()
        for name in ('control', 'ack'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd); setattr(self, name, None)
        return status


def cpu_decode(out, owners, dsos, *, symfs=None):
    symfs = out / "symfs" if symfs is None else symfs
    decoded = command('perf-script', out / 'stacks.txt', limit=16 * 1024**2, timeout=30,
                      out=out, symfs=symfs)
    attributes = command('perf-attributes', out / 'perf-attributes.txt', out=out)
    header = command('perf-header', out / 'perf-header.txt', out=out)
    buildids = command('perf-buildids', out / 'perf-buildids.txt', out=out)
    # Stream the raw decoder, retain record headers/counts only. Raw stack memory
    # stays in bounded perf.data; hex expansion cannot exhaust trace artifacts.
    records, raw_error = [], None
    with (out / 'perf-raw.stderr').open('wb') as err:
        process = launch('perf-raw', stdout=subprocess.PIPE, stderr=err, out=out)
        os.set_blocking(process.stdout.fileno(), False)
        pending = b''
        deadline = time.monotonic() + 30
        seen = 0
        while True:
            if time.monotonic() > deadline or seen > 512 * 1024**2:
                raw_error = 'raw decoder deadline/stream cap'; break
            try:
                chunk = os.read(process.stdout.fileno(), 65536)
            except BlockingIOError:
                time.sleep(0.01); continue
            if not chunk:
                if process.poll() is not None:
                    break
                time.sleep(0.01); continue
            seen += len(chunk); pending += chunk
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                if b'PERF_RECORD_' in line:
                    # Strip pointer/hex output. Keep event type and lost metadata
                    # as raw decoder text (user-only samples, never packet data).
                    tokens = line.decode(errors='replace').split('PERF_RECORD_', 1)[1]
                    records.append('PERF_RECORD_' + tokens[:256])
                if len(records) > 100000:
                    raw_error = 'raw record count cap'; break
            if raw_error:
                break
        raw_status = reap(process) if raw_error else dict(returncode=process.wait(timeout=3), forced=False)
        process.stdout.close()
    write(out / 'perf-records.json', dict(records=records, status=raw_status, incomplete=raw_error))
    result = decode_cpu((out / 'stacks.txt').read_text(errors='replace'), '\n'.join(records), set(owners))
    issues = []
    actual_attributes = (out / 'perf-attributes.txt').read_text(errors='replace')
    attributes_verified = (not attributes['returncode'] and not attributes['incomplete'] and
        'STACK_USER' in actual_attributes and 'REGS_USER' in actual_attributes and
        'TOTAL_TIME_ENABLED' in actual_attributes and 'TOTAL_TIME_RUNNING' in actual_attributes and
        bool(re.search(r'inherit\s*:\s*1\b', actual_attributes)) and
        bool(re.search(r'exclude_kernel\s*:\s*1\b', actual_attributes)) and
        bool(re.search(r'sample_(?:freq|period)\s*:\s*99\b', actual_attributes)) and
        bool(re.search(r'sample_stack_user\s*:\s*8192\b', actual_attributes)) and
        bool(re.search(r'clockid\s*:\s*1\b', actual_attributes)))
    if not attributes_verified:
        issues.append('actual software sample attributes not verified')
    build_id_by_path = {}
    for line in (out / 'perf-buildids.txt').read_text(errors='replace').splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and re.fullmatch(r'[a-fA-F0-9]{8,64}', parts[0]):
            build_id_by_path[parts[1].strip()] = parts[0].lower()
    retained_ids = {d['path']: [line.rsplit(' ', 1)[-1].lower() for line in d['build_id_lines']]
                    for d in dsos.get('dsos', [])}
    for path, build_id in build_id_by_path.items():
        if path.startswith('/') and build_id not in retained_ids.get(path, []):
            issues.append('recorded DSO build ID lacks matching retained ELF: ' + path)
    if not build_id_by_path or buildids['returncode'] or buildids['incomplete']:
        issues.append('recorded build IDs unavailable')
    if decoded['returncode'] or decoded['incomplete'] or raw_status['returncode'] or raw_error:
        issues.append('decoder failed/incomplete')
    if not result['samples'] or result['raw_sample_records'] != result['samples'] + result['foreign_samples']:
        issues.append('sample decoder coverage mismatch')
    if result['lost_records'] or result['throttle_records']:
        issues.append('lost or throttled samples')
    if result['foreign_samples']:
        issues.append('samples outside admitted process generations')
    if not dsos.get('complete') or any(not d['build_id_lines'] or not d['eh_frame'] for d in dsos.get('dsos', [])):
        issues.append('missing matching ELF/build IDs/CFI')
    if not result['mmap_records'] or not result['task_records']:
        issues.append('missing mapping/task provenance')
    if result['unresolved_samples'] or result['multi_frame_samples'] != result['samples']:
        issues.append('partial unwinding/unresolved samples')
    result.update(issues=issues, samples_complete=not issues, decoder_status=decoded,
                  header_status=header, buildid_status=buildids, attributes_status=attributes, attributes_verified=attributes_verified,
                  raw_decoder_status=raw_status, unwind_complete=False,
                  enabled_running_time='PERF_SAMPLE_READ with TOTAL_TIME_ENABLED/RUNNING in raw perf.data; actual attributes retained',
                  kernel_stacks='not selected; user-mode cpu-clock only')
    write(out / 'cpu-coverage.json', {k: v for k, v in result.items() if k not in ('callchains', 'folded')})
    (out / 'stacks.folded').write_text(''.join(f'{k} {v}\n' for k, v in result['folded'].items()))
    return result


def capabilities(out):
    paths = ['/proc/sys/kernel/random/boot_id', '/proc/sys/kernel/perf_event_paranoid',
             '/proc/sys/kernel/perf_event_max_sample_rate', '/proc/sys/kernel/perf_event_max_stack',
             '/proc/sys/kernel/perf_event_mlock_kb', '/proc/sys/kernel/unprivileged_bpf_disabled',
             '/proc/self/status', '/proc/self/limits', '/proc/self/cgroup', '/proc/cpuinfo',
             '/sys/kernel/security/lockdown', '/etc/os-release', '/etc/apt/sources.list.d/ubuntu.sources',
             '/boot/config-' + platform.release()]
    result = dict(kernel=platform.uname()._asdict(), files={p: read_metadata(p) for p in paths},
                  parents=PARENTS, clock=clock(),
                  runner={k: os.environ.get(k) for k in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')},
                  namespaces={n: Path('/proc/self/ns', n).stat().st_ino for n in ('pid', 'mnt', 'net', 'time', 'user')},
                  source_hashes={p.name: digest(p) for p in list(HERE.glob('h1_trace*')) +
                                 [p for p in (HERE / 'h3_proof').iterdir() if p.suffix in ('.h', '.c')] if p.is_file()},
                  object_hashes={p.name: digest(p) for p in STAGE.iterdir() if p.is_file()},
                  discovered=True, loaded=False, attached=False, fixture_exercised=False, gateway_observed=False)
    try:
        result['btf_sha256'] = digest('/sys/kernel/btf/vmlinux')
    except OSError as error:
        result['btf_error'] = error.errno
    for action in ('perf-version', 'clang-version', 'cc-version', 'readelf-version', 'packages', 'package-origins'):
        result[action] = command(action, out / (action + '.txt'))
    result['perf_source'] = json.loads((STAGE / 'perf-source.json').read_text())
    try:
        notes = Path('/sys/kernel/notes').read_bytes()
        if len(notes) > 1024 * 1024:
            raise ValueError('kernel ELF note bound')
        result['kernel_notes_sha256'] = hashlib.sha256(notes).hexdigest()
        offset, ids = 0, []
        while offset + 12 <= len(notes):
            namesz, descsz, kind = struct.unpack_from('=III', notes, offset)
            offset += 12
            name = notes[offset:offset + namesz]
            offset += (namesz + 3) & ~3
            value = notes[offset:offset + descsz]
            offset += (descsz + 3) & ~3
            if name.rstrip(b'\0') == b'GNU' and kind == 3:
                ids.append(value.hex())
        result['kernel_build_ids'] = ids
    except (OSError, ValueError) as error:
        result['kernel_build_id_error'] = str(error)
    result['tracepoint_formats'] = {name: read_metadata('/sys/kernel/tracing/events/' + name + '/format')
        for name in ('raw_syscalls/sys_enter', 'raw_syscalls/sys_exit', 'sched/sched_process_fork',
                     'sched/sched_process_exec', 'sched/sched_process_exit')}
    write(out / 'capabilities.json', result)
    return result


def trace_bytes(out):
    # Build/debug/DSO packages are separately bounded and excluded by contract.
    return sum(p.stat().st_size for p in out.rglob('*') if p.is_file() and
               'symfs' not in p.relative_to(out).parts)


def campaign_trace_bytes(root):
    """One job-wide trace budget, including preflight and prior failed repeats."""
    total = 0
    for path in Path(root).rglob('*'):
        parts = path.relative_to(root).parts
        if ('traces' in parts or 'trace-preflight' in parts) and 'symfs' not in parts and path.is_file():
            total += path.stat().st_size
    return total


def boundary_report(sample, timeline, start, end, owner):
    phases = sample.get('phases') or {}
    window = clock_receipt_window(phases, [row.get('clock') for row in timeline],
        boot_id=owner['boot_id'], time_namespace=owner['namespaces']['time'])
    if window.get('valid') and (start > window['start_bounds_ns'][0] or end < window['end_bounds_ns'][1]):
        window = dict(valid=False, reason='capture does not cover full measurement')
    return dict(measurement=window, capture_start_ns=start, capture_end_ns=end,
                setup_warmup_drain='client completion verified before teardown; collector end conservatively bounded',
                exact_warmup_drain_boundaries=False,
                boundary_gap='existing phase report lacks absolute warmup/drain clocks; measurement is host-bracketed',
                cumulative_deltas='snapshot read intervals, not instantaneous phase counts')


def supervise(args):
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mode = args.mode if args.enabled else 'none'
    result = dict(schema=1, mode=mode, selected_mode=args.mode, external_enabled=args.enabled,
                  parents=PARENTS, bounds=BOUNDS, complete=False, issues=[], timeline=[],
                  supervisor_started=clock(), supervisor_cpu_start=time.process_time(),
                  phase='waiting_for_owned_gateway', fully_profiled=False)
    observer = cpu = owner = lifecycle = None
    ended = result['supervisor_started']['after_ns']
    stop_requested = False
    parent = identity(args.parent)
    deadline = time.monotonic() + BOUNDS['seconds']
    try:
        if any((out / name).exists() for name in ('bind.json', 'ready.json', 'stop', 'stopped.json',
                'teardown-request.json', 'teardown-ready.json', 'trace-manifest.json')):
            raise RuntimeError('stale capture directory; lifecycle evidence must be fresh')
        if campaign_trace_bytes(Path(args.artifact_root)) >= BOUNDS['total_artifact_bytes'] - 32 * 1024**2:
            raise RuntimeError('job trace artifact reservation already exhausted')
        capabilities(out)
        if mode == 'syscalls':
            observer = Observer(out)
            result['ready'] = observer.ready
        # Supervisor exists before start_ferrum. This receipt is not collector readiness.
        write(out / 'supervisor-ready.json', dict(pid=os.getpid(), at=clock(), awaiting_binding=True))
        while not (out / 'bind.json').exists():
            if (out / 'stop').exists() or time.monotonic() >= deadline:
                raise RuntimeError('binding absent before stop/deadline')
            if parse_stat(Path(f'/proc/{args.parent}/stat').read_text(), TICKS, PAGE)['start_ticks'] != parent['start_ticks']:
                raise RuntimeError('parent generation changed')
            time.sleep(0.05)
        binding = json.loads((out / 'bind.json').read_text())
        runtime = json.loads(Path(binding['runtime']).read_text())
        config = Path(binding['config']).read_bytes()
        expected = (HERE / 'configs/http1_tls_e2e_perf.yaml').read_text().replace('CA_PATH', '/etc/ferrum/tls/ca.pem').encode()
        if config != expected or hashlib.sha256(config).hexdigest() != runtime['config_sha256']:
            raise ValueError('effective config does not match exact H1 TLS fixture')
        env = runtime['environment']
        for key, value in {'FERRUM_MODE': 'file', 'FERRUM_PROXY_HTTPS_PORT': '8443',
                           'FERRUM_ADMIN_HTTP_PORT': '9000', 'FERRUM_ADMIN_BIND_ADDRESS': '127.0.0.1'}.items():
            if env.get(key) != value:
                raise ValueError('runtime role configuration mismatch: ' + key)
        if env.get('FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES') not in ('0', '1'):
            raise ValueError('unexpected cutoff')
        owner = identity(runtime['host_pid']); admit(owner)
        builds = Path(args.builds).resolve()
        matches = [str(p.relative_to(builds)) for p in builds.glob('*/ferrum-edge') if digest(p) == owner['executable_sha256']]
        if len(matches) != 1:
            raise ValueError('target ELF does not match exactly one retained release twin')
        result.update(identity=owner, runtime=runtime, matching_elf=matches[0], binding=binding)
        write(out / 'identity.json', owner)
        result['initial_sockets'] = tcp_inventory(owner['pid'])
        write(out / 'initial-sockets.json', result['initial_sockets'])
        symbol_package = builds / Path(matches[0]).parent / 'symfs'
        result['symbol_package'] = str(symbol_package)
        dsos = retain_dsos(owner['pid'], symbol_package) if mode == 'cpu' else {}
        write(out / 'build-mappings.json', dsos)
        if observer and observer.ready.get('status') == 'supported':
            result['binding_receipt'] = observer.bind(owner)
        if mode == 'cpu':
            cpu = CPU(out, owner); result['ready'] = cpu.ready
        if mode == 'none':
            result['ready'] = dict(status='off', at=clock())
        started = time.monotonic_ns()
        ready = dict(status=result['ready']['status'], at=clock_receipt(), owner=owner,
                     session=os.urandom(16).hex(), binding_sha256=digest(out / 'bind.json'),
                     deadline_monotonic=deadline, cookie_priming_errors=result['initial_sockets']['errors'])
        lifecycle = CaptureLifecycle(out, owner, binding, ready, dict(cpu=cpu, observer=observer))
        lifecycle.poll()
        result['timeline'].append(dict(clock=ready['at'], ready=True))
        write(out / 'ready.json', ready)
        next_snapshot = 0
        while time.monotonic() < deadline:
            if observer:
                observer.poll()
            lifecycle.poll()
            lifecycle.authorize_teardown()
            if (out / 'stop').exists():
                stop_requested = True
                lifecycle.verify_stop()
                break
            if campaign_trace_bytes(Path(args.artifact_root)) >= BOUNDS['total_artifact_bytes'] - 32 * 1024**2:
                raise RuntimeError('trace artifact reservation exhausted')
            raw = out / 'perf.data'
            if raw.exists() and raw.stat().st_size >= BOUNDS['raw_perf_bytes']:
                raise RuntimeError('raw perf artifact cap reached')
            usage = lifecycle.usage()
            rss = sum(p['rss_bytes'] for p in usage if p)
            result['observer_peak_rss_bytes'] = max(result.get('observer_peak_rss_bytes', 0), rss)
            if rss + (BOUNDS['map_reservation_bytes'] if observer else 0) > BOUNDS['observer_rss_and_map_bytes']:
                raise RuntimeError('observer RSS/map reservation exceeded')
            if time.monotonic() >= next_snapshot:
                next_snapshot = time.monotonic() + 5
                sample = dict(clock=clock_receipt(), observer_usage=usage, observer_rss_bytes=rss)
                if len(result['timeline']) >= BOUNDS['metadata_snapshots']:
                    raise RuntimeError('metadata snapshot cap')
                try:
                    current = identity(owner['pid'])
                    if not same_generation(owner, current):
                        raise RuntimeError('gateway process/executable/namespace generation changed')
                    sample['identity'] = current
                    sample['tcp'] = tcp_inventory(owner['pid'])
                except FileNotFoundError:
                    if lifecycle.teardown is None:
                        raise RuntimeError('gateway vanished before verified teardown')
                    sample['gateway_gone'] = True
                result['timeline'].append(sample)
            if (not Path(f'/proc/{args.parent}').exists() or
                parse_stat(Path(f'/proc/{args.parent}/stat').read_text(), TICKS, PAGE)['start_ticks'] != parent['start_ticks']):
                raise RuntimeError('owned harness vanished/reused')
            time.sleep(0.05)
        if not stop_requested:
            raise RuntimeError('capture deadline: measurement/warmup/drain may be incomplete')
        ended = time.monotonic_ns()
        if len(result['timeline']) >= BOUNDS['metadata_snapshots']:
            raise RuntimeError('metadata snapshot cap')
        result['timeline'].append(dict(clock=clock_receipt(), terminal=True))
        sample = {}
        try:
            sample = json.loads(Path(binding['sample']).read_text())
        except (OSError, ValueError):
            result['issues'].append('missing/failed raw traffic sample')
        result['boundaries'] = boundary_report(sample, result['timeline'], started, lifecycle.coverage_end(ended), owner)
        if not result['boundaries']['measurement'].get('valid'):
            result['issues'].append('capture measurement clock/coverage incomplete')
        result['useful_work'] = dict(sample=str(binding['sample']), validity='independent existing benchmark_validity contract')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as error:
        result['issues'].append(type(error).__name__ + ': ' + str(error))
    finally:
        if observer:
            result['observer_exit'] = observer.finish()
            if lifecycle:
                lifecycle.reaped('observer', result['observer_exit'])
            result['syscalls'] = syscall_coverage(observer.rows, owner or {}, result.get('boundaries', {}))
            if result['observer_exit']['forced'] or result['observer_exit']['returncode'] or result['observer_exit']['partial_record']:
                result['issues'].append('observer exit incomplete')
            if not result['syscalls'].get('complete'):
                result['issues'].append('syscall coverage incomplete')
            write(out / 'syscalls.json', result['syscalls'])
            write(out / 'fd-lifetimes.json', fd_lifetimes(observer.rows))
        if cpu:
            result['perf_exit'] = cpu.finish()
            if lifecycle:
                lifecycle.reaped('cpu', result['perf_exit'])
            if (out / 'perf.data').exists():
                try:
                    decoded_cpu = cpu_decode(out, [owner['pid']] if owner else [], dsos, symfs=symbol_package)
                    from h1_trace_contract import cpu_phases
                    result['cpu'] = {k: v for k, v in decoded_cpu.items() if k not in ('callchains', 'folded')}
                    result['cpu']['phases'] = cpu_phases(decoded_cpu['callchains'], result.get('boundaries', {}).get('measurement', {}))
                    result['issues'].extend('CPU capture: ' + issue for issue in decoded_cpu['issues'] if issue not in (
                        'missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples'))
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                    result['issues'].append('CPU decoder failed: ' + str(error))
            if result['perf_exit']['forced'] or result['perf_exit']['returncode']:
                result['issues'].append('perf exit incomplete')
            if not (out / 'perf.data').exists():
                result['issues'].append('missing perf data')
        if lifecycle:
            result['lifecycle'] = lifecycle.report()
            result['lifecycle']['collectors_reaped_at'] = clock()
        result.update(stop_requested=stop_requested, ended=clock(), artifact_bytes=trace_bytes(out),
                      supervisor_cpu_seconds=time.process_time() - result['supervisor_cpu_start'])
        if result.get('ready', {}).get('status') not in ('supported', 'off'):
            result['issues'].append('collector unsupported/unavailable')
        result['job_trace_artifact_bytes'] = campaign_trace_bytes(Path(args.artifact_root))
        if result['job_trace_artifact_bytes'] > BOUNDS['total_artifact_bytes']:
            result['issues'].append('total trace artifact cap exceeded')
        result['coverage_gaps'] = ['gateway startup before verified binding', 'absolute warmup/drain phase boundaries',
                                   'full native allocation/copy coverage', 'optimized-away/async frames',
                                   'IPv6 role attribution and unproven shared-file-table lifetimes']
        # Full profiling cannot be certified by one separately selected dimension.
        result['complete'] = False
        result['capture_complete'] = stop_requested and not result['issues']
        try:
            capability = json.loads((out / 'capabilities.json').read_text())
            capability['loaded'] = mode == 'syscalls' and result.get('ready', {}).get('status') == 'supported'
            capability['attached'] = mode != 'none' and result.get('ready', {}).get('status') == 'supported'
            capability['gateway_observed'] = bool(result.get('cpu', {}).get('samples') or
                any(r.get('exits') for r in result.get('syscalls', {}).get('syscall_totals', [])))
            capability['capture_complete'] = result['capture_complete']
            write(out / 'capabilities.json', capability)
        except (OSError, ValueError):
            result['issues'].append('capability completion record missing')
            result['capture_complete'] = False
        result['artifacts'] = {str(p.relative_to(out)): dict(sha256=digest(p), bytes=p.stat().st_size)
            for p in out.rglob('*') if p.is_file() and 'symfs' not in p.relative_to(out).parts
            and p.name not in ('trace-manifest.json', 'stopped.json')}
        write(out / 'trace-manifest.json', result)
        write(out / 'stopped.json', dict(at=clock(), issues=result['issues'], capture_complete=result['capture_complete']))
    return 0 if result['capture_complete'] else 1


def stage(build):
    # A fresh public traversal path for ordinary-UID fixtures, never chmod checkout.
    STAGE.mkdir(mode=0o755)
    for name in ('observer', 'observer.bpf.o', 'h1_trace_fixture'):
        source = Path(build) / name
        destination = STAGE / name
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o644 if name.endswith('.o') else 0o755)
    # Ubuntu's /usr/bin/perf wrapper often expects an unavailable Azure kernel
    # package. Retain the actual distro ELF from installed linux-tools-generic;
    # do not download a tool or assume its package version matches the kernel.
    candidates = sorted({p.resolve() for p in Path('/usr/lib/linux-tools').glob('*/perf') if p.is_file()})
    if not candidates:
        raise ValueError('installed Ubuntu perf ELF missing')
    perf = candidates[-1]
    with perf.open('rb') as source:
        if source.read(4) != b'\x7fELF':
            raise ValueError('perf is not an ELF')
    (STAGE / 'perf').write_bytes(perf.read_bytes())
    (STAGE / 'perf').chmod(0o755)
    write(STAGE / 'perf-source.json', dict(installed_path=str(perf), sha256=digest(perf)))
    (STAGE / 'buildid-cache').mkdir(mode=0o700)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    s = sub.add_parser('stage'); s.add_argument('--build', required=True)
    s = sub.add_parser('supervise')
    s.add_argument('--output', required=True); s.add_argument('--builds', required=True)
    s.add_argument('--artifact-root', required=True)
    s.add_argument('--mode', choices=('syscalls', 'cpu'), required=True)
    s.add_argument('--enabled', action='store_true'); s.add_argument('--parent', type=int, required=True)
    s = sub.add_parser('preflight'); s.add_argument('--output', required=True)
    s = sub.add_parser('request-teardown'); s.add_argument('--output', required=True)
    s = sub.add_parser('bind')
    for field in ('output', 'runtime', 'config', 'sample', 'raw-sample', 'client-exit', 'arm'):
        s.add_argument('--' + field, required=True)
    s.add_argument('--pair', type=int, required=True); s.add_argument('--payload', type=int, required=True)
    args = parser.parse_args()
    if (os.environ.get('GITHUB_ACTIONS'), os.environ.get('RUNNER_ENVIRONMENT'), platform.system(), platform.machine()) != (
            'true', 'github-hosted', 'Linux', 'x86_64'):
        raise SystemExit('hosted native amd64 passive supervisor only')
    if args.action == 'request-teardown':
        request_teardown(args.output); return 0
    if args.action == 'bind':
        write_binding(args.output, runtime=args.runtime, config=args.config, sample=args.sample,
                      arm=args.arm, pair=args.pair, payload=args.payload,
                      raw_sample=args.raw_sample, client_exit=args.client_exit)
        return 0
    if os.geteuid() != 0:
        raise SystemExit('hosted passive supervisor requires root')
    if args.action == 'stage':
        stage(args.build); return 0
    if not Path('/sys/kernel/tracing/events').exists():
        command('tracefs', Path(args.output) / 'tracefs.txt')
    if args.action == 'supervise':
        return supervise(args)
    from h1_trace_preflight import preflight
    return preflight(Path(args.output))


if __name__ == '__main__':
    sys.exit(main())
