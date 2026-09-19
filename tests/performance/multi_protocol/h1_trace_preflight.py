"""Actual hosted fixtures for the H1 producer/consumer boundary, never gateway proof."""
import json
from pathlib import Path
import subprocess
import time

from h1_trace import (Observer, CPU, launch, reap, identity, admit, same_generation,
                      tcp_inventory, retain_dsos, cpu_decode, capabilities, write, clock, CaptureLifecycle)
from h1_trace_contract import LOSSES, SYSCALLS, fd_lifetimes, syscall_coverage, nested_fixture_proof


class Fixture:
    def __init__(self, out, mode):
        self.out = out
        self.stdout = (out / 'fixture.jsonl').open('wb')
        self.stderr = (out / 'fixture.stderr').open('wb')
        self.process = launch('fixture', stdout=self.stdout, stderr=self.stderr,
                              stdin=subprocess.PIPE, mode=mode)
        self.rows = []
        self.offset = 0
        self.pending = b''
        self.wait('ready')
        self.owner = identity(self.process.pid)
        admit(self.owner)

    def poll(self):
        with (self.out / 'fixture.jsonl').open('rb') as stream:
            stream.seek(self.offset); chunk = stream.read(1024 * 1024)
            self.offset += len(chunk)
        self.pending += chunk
        while b'\n' in self.pending:
            line, self.pending = self.pending.split(b'\n', 1)
            self.rows.append(json.loads(line))
        if self.offset > 1024 * 1024:
            raise RuntimeError('fixture output cap')

    def wait(self, phase):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.poll()
            row = next((r for r in self.rows if r.get('phase') == phase), None)
            if row:
                return row
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError('fixture missing ' + phase)

    def release(self):
        self.process.stdin.write(b'g'); self.process.stdin.flush()

    def finish(self):
        status = reap(self.process)
        self.poll()
        self.stdout.close(); self.stderr.close()
        return status


def reconcile(calls, events):
    candidates = [dict(e) for e in events if e.get('phase') == 'h1_event' and e.get('kind') == 1]
    errors, covered = [], set()
    for call in calls:
        if call.get('phase') != 'call' or call['id'] not in SYSCALLS:
            continue
        outer = call['result'] if call['result'] >= 0 else -call['errno']
        match = next((e for e in candidates if all(e[k] == call[k] for k in ('pid', 'tid', 'fd', 'id'))
                      and (e['result'] == outer or call['errno'] == 4 and e['result'] in (-512, -513, -514, -516))
                      and (not call['offered'] or not e['known'] or e['offered'] == call['offered'])), None)
        if match is None:
            errors.append('unreconciled fixture call: ' + call['label']); continue
        candidates.remove(match)
        covered.add(SYSCALLS[call['id']])
        if call['id'] in (299, 307) and outer > 0 and match['accepted_known'] and match['accepted'] != outer * 12:
            errors.append('batch returned-prefix length mismatch')
        if call['id'] not in (299, 307) and outer >= 0 and match['accepted'] != outer:
            errors.append('byte return mismatch')
    return dict(errors=errors, covered_syscalls=sorted(covered), claimed_gateway_coverage=False)


def syscall_fixture(out, *, capacity='8192', generation_fault=False):
    observer = fixture = unrelated = None
    result = dict(fixture_only=True, status='error', errors=[])
    try:
        observer = Observer(out, capacity=capacity)
        result['ready'] = observer.ready
        if observer.ready['status'] != 'supported':
            result['status'] = observer.ready['status']; return result
        fixture = Fixture(out, 'syscalls')
        unrelated_path = out / 'unrelated'; unrelated_path.mkdir()
        unrelated = Fixture(unrelated_path, 'cpu')
        target = dict(fixture.owner)
        if generation_fault:
            target['start_ticks'] += 1
        result['bound'] = observer.bind(target)
        result['initial_inventory'] = tcp_inventory(fixture.owner['pid'])
        unrelated.release(); fixture.release()
        prime_count = 0
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline and fixture.process.poll() is None:
            fixture.poll(); observer.poll()
            new = sum(r['phase'] == 'prime' for r in fixture.rows)
            if new > prime_count:
                result.setdefault('cookie_priming', []).append(tcp_inventory(fixture.owner['pid']))
                fixture.release(); prime_count = new
            time.sleep(0.02)
        fixture.poll()
        result['fixture_exit'] = fixture.process.poll()
        if result['fixture_exit'] != 0:
            result['errors'].append('fixture failed or timed out')
        result['observer_exit'] = observer.finish()
        rows = observer.rows
        final = next((r for r in rows if r['phase'] == 'final'), {})
        losses = dict(zip(LOSSES, final.get('losses', [])))
        result['losses'] = losses
        result['identity'] = fixture.owner
        result['lifetime'] = fd_lifetimes(rows)
        events = [r for r in rows if r['phase'] == 'h1_event']
        if any(r.get('pid') == unrelated.owner['pid'] for r in events):
            result['errors'].append('same-namespace unrelated process included')
        if generation_fault:
            if not losses.get('generation') or final.get('totals'):
                result['errors'].append('stale process generation accepted')
        elif capacity == '1':
            if not losses.get('map_full'):
                result['errors'].append('capacity loss not exercised')
        else:
            result['reconciliation'] = reconcile(fixture.rows, events)
            result['errors'].extend(result['reconciliation']['errors'])
            if set(result['reconciliation']['covered_syscalls']) != set(SYSCALLS.values()):
                result['errors'].append('missing exercised syscall')
            roles = {r.get('role') for r in events}
            if not {1, 2, 3, 4, 5} <= roles:
                result['errors'].append('missing frontend/upstream/excluded roles')
            for expected in ('read_failed', 'vector_bound', 'unsupported'):
                if not losses.get(expected):
                    result['errors'].append('negative path not observed: ' + expected)
            totals = final.get('totals', [])
            if not any(r['short_calls'] for r in totals) or not any(r['eof'] for r in totals):
                result['errors'].append('partial/EOF path not observed')
        result['status'] = 'supported' if not result['errors'] else 'error'
        result['declared_unexercised'] = ['actual PID number recycling (stale generation rejection exercised)',
            'SCM_RIGHTS/pidfd_getfd shared file tables', 'compat and IPv6',
            'nondeterministic close-during-inflight TCP race (no FD join is used)',
            'all gateway API paths; fixture evidence is never gateway evidence']
    finally:
        if observer and not observer.raw.closed:
            result['observer_exit'] = observer.finish()
        for process in (fixture, unrelated):
            if process:
                result.setdefault('fixture_cleanup', []).append(process.finish())
        write(out / 'result.json', result)
    return result


def cpu_fixture(out):
    fixture = unrelated = cpu = lifecycle = None
    result = dict(fixture_only=True, status='error', errors=[])
    try:
        fixture = Fixture(out, 'cpu-teardown')
        other = out / 'unrelated'; other.mkdir()
        unrelated = Fixture(other, 'cpu')
        dsos = retain_dsos(fixture.owner['pid'], out / 'symfs')
        write(out / 'build-mappings.json', dsos)
        cpu = CPU(out, fixture.owner)
        result['ready'] = cpu.ready
        if cpu.ready['status'] != 'supported':
            result['status'] = 'unsupported'; return result
        result['owner'] = fixture.owner
        owners = {fixture.owner['pid']: fixture.owner}
        cpu_start = clock()
        lifecycle = CaptureLifecycle(out, fixture.owner, {},
            dict(session='hosted-cpu-fixture', binding_sha256=None, at=cpu_start), dict(cpu=cpu))
        lifecycle.poll()
        fixture.release(); unrelated.release()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and fixture.process.poll() is None:
            fixture.poll()
            lifecycle.poll()
            for row in fixture.rows:
                if row['phase'] == 'child' and row['pid'] not in owners:
                    try:
                        child = identity(row['pid']); admit(child)
                        if child['executable_sha256'] != fixture.owner['executable_sha256']:
                            raise ValueError('child executable mismatch')
                        owners[row['pid']] = child
                    except FileNotFoundError:
                        result['errors'].append('missed child generation')
            if any(row['phase'] == 'workload_done' for row in fixture.rows):
                receipt = next(row for row in fixture.rows if row['phase'] == 'workload_done')
                lifecycle.acknowledge_teardown(dict(fixture_only=True, receipt=receipt, retained_at=clock()),
                                               dict(kind='fixture_joined_threads_and_child', gateway_coverage=False))
                result['teardown_release'] = clock()
                fixture.release()
                break
            time.sleep(0.02)
        if lifecycle.teardown is None:
            raise RuntimeError('fixture work did not finish before teardown deadline')
        # Observe the real perf autoexit without SIGINT; this exercises the
        # same consumer as gateway removal. No added delay guesses correctness.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            lifecycle.poll()
            if 'exit' in lifecycle.observations['cpu']:
                break
            time.sleep(0.02)
        else:
            result['errors'].append('perf did not autoexit after fixture teardown')
        result['fixture_exit'] = fixture.process.poll()
        result['capture_start'] = cpu_start
        result['perf_exit'] = cpu.finish()
        lifecycle.reaped('cpu', result['perf_exit'])
        result['lifecycle'] = lifecycle.report()
        if result['perf_exit']['returncode'] or result['perf_exit']['forced']:
            result['errors'].append('perf exit incomplete')
        result['owners'] = list(owners.values())
        result['cpu'] = cpu_decode(out, owners, dsos)
        result['partial_unwind_issues'] = result['cpu']['issues']
        result['errors'].extend(i for i in result['cpu']['issues'] if i not in (
            'missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples'))
        result['nested_proof'] = nested_fixture_proof(result['cpu']['callchains'])
        if not result['nested_proof']['proven']:
            result['errors'].append('known nested fixture chain not reconstructed')
        child_pids = set(owners) - {fixture.owner['pid']}
        seen_pids = {s['pid'] for s in result['cpu']['callchains']}
        if len(result['cpu']['per_tid']) < 4 or not child_pids or not child_pids <= seen_pids:
            result['errors'].append('thread/post-attach child sampling missing')
        if result['fixture_exit'] != 0:
            result['errors'].append('fixture did not exit successfully')
        result['status'] = 'supported' if not result['errors'] else 'error'
        # Actual missing-symbol/unwind package: decode the same samples against
        # an empty symfs. A decode exit of zero cannot imply useful stacks.
        from h1_trace import command
        from h1_trace_contract import decode_cpu
        missing = out / 'empty-symfs'; missing.mkdir()
        status = command('perf-script', out / 'missing-symbols.txt', out=out, symfs=missing)
        missing_cpu = decode_cpu((out / 'missing-symbols.txt').read_text(errors='replace'), '', set(owners))
        result['missing_unwind_package'] = dict(status=status, unresolved=missing_cpu['unresolved_samples'], samples=missing_cpu['samples'])
        if status['returncode'] == 0 and missing_cpu['unresolved_samples'] == 0:
            result['status'] = 'error'; result['errors'].append('missing unwind package not detected')
        # Real corrupt-data decoder failure, not an assertion about constants.
        negative = out / 'corrupt'; negative.mkdir()
        (negative / 'perf.data').write_bytes(b'not a perf capture\n')
        from h1_trace import command
        result['decoder_negative'] = command('perf-script', negative / 'decoded.txt', out=negative, symfs=out / 'symfs')
        if result['decoder_negative']['returncode'] == 0:
            result['status'] = 'error'; result['errors'].append('corrupt capture accepted')
    finally:
        if cpu:
            result['perf_cleanup'] = cpu.finish()
        if lifecycle:
            result['lifecycle'] = lifecycle.report()
        for process in (fixture, unrelated):
            if process:
                result.setdefault('fixture_cleanup', []).append(process.finish())
        write(out / 'result.json', result)
    return result



def cpu_cap_fixture(out):
    """Actual perf write cap kills an owned capture; never a completed trace."""
    fixture = cpu = None
    result = dict(status='error', fixture_only=True, incomplete=True)
    try:
        fixture = Fixture(out, 'cpu')
        cpu = CPU(out, fixture.owner, file_limit=64 * 1024)
        result['ready'] = cpu.ready
        if cpu.ready['status'] != 'supported':
            result['status'] = 'unsupported'; return result
        fixture.release()
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and cpu.process.poll() is None:
            time.sleep(0.02)
        result['capture_exit'] = cpu.finish()
        result['raw_bytes'] = (out / 'perf.data').stat().st_size
        if result['raw_bytes'] <= 64 * 1024 and result['capture_exit']['returncode'] != 0:
            result['status'] = 'supported'
    finally:
        if cpu:
            result['perf_cleanup'] = cpu.finish()
        if fixture:
            result['fixture_cleanup'] = fixture.finish()
        write(out / 'result.json', result)
    return result


def preflight(out):
    out.mkdir(parents=True, exist_ok=True)
    capabilities(out)
    results = {}
    for name, kwargs in [('syscalls', {}), ('map-capacity', {'capacity': '1'}),
                         ('generation-rejection', {'generation_fault': True})]:
        folder = out / name; folder.mkdir()
        try:
            results[name] = syscall_fixture(folder, **kwargs)
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            results[name] = dict(status='error', error=str(error))
    for name, kwargs in [('missing-btf', {'fault': 'missing-btf'}),
                         ('missing-symbol', {'fault': 'missing-symbol'}),
                         ('permission', {'denied': 'true'})]:
        folder = out / name; folder.mkdir()
        observer = None
        try:
            observer = Observer(folder, **kwargs)
            results[name] = dict(ready=observer.ready,
                                 status='supported' if observer.ready['status'] != 'supported' else 'error')
        except (OSError, ValueError, RuntimeError) as error:
            results[name] = dict(status='error', error=str(error))
        finally:
            if observer:
                results[name]['exit'] = observer.finish()
    folder = out / 'cpu'; folder.mkdir()
    try:
        results['cpu'] = cpu_fixture(folder)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        results['cpu'] = dict(status='error', error=str(error))
    folder = out / 'cpu-cap'; folder.mkdir()
    try:
        results['cpu-cap'] = cpu_cap_fixture(folder)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        results['cpu-cap'] = dict(status='error', error=str(error))
    result = dict(schema=1, fixture_only=True, results=results,
                  gateway_coverage=False, issue_5588_closed=False,
                  status='error' if any(r['status'] == 'error' for r in results.values()) else 'supported_or_explicitly_unsupported')
    write(out / 'preflight.json', result)
    return int(result['status'] == 'error')
