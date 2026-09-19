"""Fixed H1 external evidence consumers. Unknown evidence never becomes zero."""
import collections
import json
import re
from pathlib import Path

SYSCALLS = {0: 'read', 1: 'write', 19: 'readv', 20: 'writev', 44: 'sendto',
            45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg', 299: 'recvmmsg', 307: 'sendmmsg'}
UNSUPPORTED = {17, 18, 40, 275, 276, 278, 295, 296, 327, 328, 425, 426, 427}
LOSSES = ('map_full', 'read_failed', 'unknown_cookie', 'nested', 'unmatched',
          'abandoned', 'ring_full', 'witness_cap', 'compat', 'generation', 'exec',
          'vector_bound', 'overflow', 'multi_socket', 'inner_unmatched', 'unsupported')
ROLES = {0: 'unknown', 1: 'frontend_send', 2: 'frontend_recv', 3: 'upstream_send',
         4: 'upstream_recv', 5: 'excluded_target_socket'}
COUNTERS = ('attempts', 'exits', 'positive', 'zero', 'errors', 'restarts', 'eof',
            'short_calls', 'offered', 'offered_known', 'accepted_bytes', 'accepted_known',
            'return_sum', 'effective_bytes', 'inner_calls', 'inner_bytes', 'inner_errors', 'elapsed_ns')
BOUNDS = dict(observer_rss_and_map_bytes=32 * 1024**2, map_reservation_bytes=8 * 1024**2,
              seconds=300, snapshots=64, raw_perf_bytes=64 * 1024**2,
              total_artifact_bytes=128 * 1024**2, aggregate_rows=8192, pending=512,
              vectors=16, witnesses=4096, lifecycle_rows=8192, metadata_snapshots=64,
              fd_rows_per_snapshot=2048, threads=512)


def natural(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def validate_record(row):
    if not isinstance(row, dict) or row.get('phase') not in (
            'ready', 'bound', 'h1_event', 'snapshot', 'checkpoint', 'final', 'termination'):
        raise ValueError('unknown H1 observer record')
    if row['phase'] in ('snapshot', 'checkpoint', 'final'):
        if len(row.get('losses', [])) != len(LOSSES) or not all(map(natural, row['losses'])):
            raise ValueError('loss schema')
        if not all(natural(row.get(k)) for k in ('before_ns', 'after_ns', 'pending', 'map_read_failures')):
            raise ValueError('snapshot metadata')
        if row['after_ns'] < row['before_ns'] or len(row['rows']) > BOUNDS['aggregate_rows']:
            raise ValueError('snapshot bounds')
        for item in row['rows'] + row['totals']:
            if not all(natural(item.get(k)) for k in COUNTERS) or item.get('id') not in SYSCALLS:
                raise ValueError('syscall counter schema')
            if row['phase'] == 'final' and item['exits'] != item['positive'] + item['zero'] + item['errors'] + item['restarts']:
                raise ValueError('return classification mismatch')
            if not all(type(item.get(k)) is int and -(2**63) <= item[k] < 2**63
                       for k in ('min_return', 'max_return')):
                raise ValueError('signed return schema')
        for item in row['rows']:
            if item.get('role') not in ROLES or not all(natural(item.get(k)) for k in
                    ('pid', 'process_ns', 'cgroup', 'cookie', 'netns')):
                raise ValueError('socket identity schema')
            if item['role'] in (1, 2, 3, 4) and not item['cookie']:
                raise ValueError('zero-cookie role join')
    return row


def syscall_coverage(rows, identity, boundaries):
    issues = []
    try:
        for row in rows:
            validate_record(row)
    except (ValueError, KeyError, TypeError) as error:
        return dict(available=False, complete=False, issues=['invalid producer: ' + str(error)])
    final = [r for r in rows if r['phase'] == 'final']
    ready = [r for r in rows if r['phase'] == 'ready']
    bound = [r for r in rows if r['phase'] == 'bound']
    terminal = [r for r in rows if r['phase'] == 'termination']
    if len(final) != 1 or len(ready) != 1 or ready[0].get('status') != 'supported':
        return dict(available=False, complete=False, issues=['missing supported ready/final'], ready=ready)
    final = final[0]
    losses = dict(zip(LOSSES, final['losses']))
    if len(bound) != 1 or bound[0].get('pid') != identity.get('pid') or bound[0].get('start_ticks') != identity.get('start_ticks'):
        issues.append('process binding missing/mismatched')
    if len(terminal) != 1 or terminal[0].get('requested_stop') is not True:
        issues.append('missing requested termination')
    if final['pending'] or final['map_read_failures']:
        issues.append('pending calls or failed map reads')
    snapshots = [r for r in rows if r['phase'] in ('checkpoint', 'snapshot', 'final')]
    reset = False
    for a, b in zip(snapshots, snapshots[1:]):
        previous = {r['id']: r for r in a['totals']}
        current = {r['id']: r for r in b['totals']}
        if any(i not in current or any(current[i][k] < v[k] for k in COUNTERS)
               for i, v in previous.items()):
            reset = True
    if reset:
        issues.append('counter reset or inconsistent snapshot')
    total_loss = ('map_full', 'nested', 'unmatched', 'abandoned', 'compat', 'generation', 'exec', 'overflow')
    issues.extend(name for name in total_loss if losses[name])
    if not boundaries.get('measurement', {}).get('valid'):
        issues.append('missing measurement clock/coverage')
    attempted = {r['id']: r['attempts'] for r in final['totals']}
    if any(final['census'].get(str(call), 0) != attempted.get(call, 0) for call in SYSCALLS):
        issues.append('syscall census/attempt mismatch')
    for r in final['totals']:
        if r['attempts'] != r['exits']:
            issues.append('unpaired attempts/exits')
    phase_delta = dict(complete=False, reason='missing bracketing snapshots')
    window = boundaries.get('measurement', {})
    if window.get('valid') and 'start_bounds_ns' in window:
        before = [r for r in snapshots if r['after_ns'] <= window['start_bounds_ns'][0]]
        after = [r for r in snapshots if r['before_ns'] >= window['end_bounds_ns'][1]]
        if before and after and not reset:
            left, right = before[-1], after[0]
            prior = {r['id']: r for r in left['totals']}
            values = []
            for r in right['totals']:
                values.append(dict(id=r['id'], **{k: r[k] - prior.get(r['id'], {}).get(k, 0) for k in COUNTERS}))
            roles = {role: {k: v[k] - left.get('role_totals', {}).get(role, {}).get(k, 0) for k in COUNTERS}
                     for role, v in right.get('role_totals', {}).items()}
            phase_delta = dict(complete=True, totals=values, roles=roles,
                               left_read_ns=[left['before_ns'], left['after_ns']],
                               right_read_ns=[right['before_ns'], right['after_ns']],
                               boundary_uncertainty_ns=(window['start_bounds_ns'][1] - left['before_ns'] +
                                                        right['after_ns'] - window['end_bounds_ns'][0]),
                               crossing_calls='counts are exit-positioned; in-flight cross-boundary work cannot be split')
    foreign = [r for r in final['rows'] if r['pid'] != identity.get('pid') or
               r['process_ns'] // 10_000_000 != identity.get('start_ticks') or
               r['cgroup'] != identity.get('cgroup_id')]
    if foreign:
        issues.append('foreign process generation')
    socket_issues = [n for n in ('read_failed', 'unknown_cookie', 'vector_bound', 'multi_socket', 'inner_unmatched') if losses[n]]
    if any(r['role'] == 0 for r in final['rows']):
        socket_issues.append('unattributed process syscalls (includes non-socket descriptors)')
    unsupported = {k: v for k, v in final['census'].items() if int(k) in UNSUPPORTED}
    if unsupported or losses['compat']:
        socket_issues.append('unsupported path census')
    # Lifetimes are an event stream, distinct from totals. FD records never grant roles.
    lifetime_complete = not any(losses[n] for n in ('ring_full', 'generation', 'exec')) and not any(
        t.get('lifecycle_omitted') or t.get('checkpoints_omitted') or t.get('snapshot_failures') for t in terminal)
    return dict(available=True, complete=not issues, issues=sorted(set(issues)), losses=losses,
                syscall_totals=final['totals'], socket_rows=final['rows'], census=final['census'],
                unsupported_census=unsupported, reset=reset, measurement_delta=phase_delta,
                measurement_complete=not issues and phase_delta["complete"],
                offered_length_complete=not issues and all(r['offered_known'] == r['exits'] for r in final['totals']),
                successful_return_bytes_complete=not issues and all(r['accepted_known'] == r['exits'] for r in final['totals']),
                socket_roles_complete=not issues and not socket_issues,
                socket_role_issues=socket_issues, lifecycle_stream_complete=lifetime_complete,
                exact_lifetimes_complete=False,
                lifetime_limit='entry FD/dup/close intervals are observations; shared files, SCM_RIGHTS, close races and prebind lifetimes remain unproven',
                witness_complete=not losses['witness_cap'] and lifetime_complete,
                attribution='actual TCP context only; no exit-time FD joins',
                min_max_timestamp_consistency='approximate under concurrent writers; cumulative totals atomic',
                walltime_is_cpu=False, accepted_is_peer_delivery=False)


def fd_lifetimes(rows):
    """Conservative entry/exit intervals; never use these to assign a socket role."""
    active, intervals, hazards = {}, [], []
    for row in rows:
        if row.get('phase') != 'h1_event':
            continue
        if row.get('kind') == 4:
            hazards.append('task exit; file-table sharing unknown')
        if row.get('kind') != 2:
            continue
        key = (row['pid'], row['process_ns'], row['fd'])
        call, result = row['id'], row['result']
        record = {k: row[k] for k in ('pid', 'process_ns', 'tid', 'fd', 'id', 'entered_ns', 'exited_ns', 'result', 'arg1', 'arg2')}
        record.update(cookie=None, role='unknown', alias_of=None, closure_proven=False)
        if result >= 0 and call in (41, 43, 288, 32, 33, 292):
            new = (row['pid'], row['process_ns'], result)
            if new in active:
                active[new]['retired_by_reuse_at_ns'] = row['exited_ns']
            record['new_fd'] = result
            if call in (32, 33, 292):
                record['alias_of'] = row['fd']
            active[new] = record
        elif call == 3:
            previous = active.pop(key, None)
            if previous:
                previous['close_observation'] = record
        elif call in (53, 72, 272, 436, 438):
            hazards.append('socketpair/fcntl/unshare/close_range/pidfd_getfd requires unproven file-table association')
            active.clear()
        intervals.append(record)
    return dict(intervals=intervals, hazards=sorted(set(hazards)), exact_alias_join=False,
                inherited_and_SCM_RIGHTS='unsupported; no role propagation')


def decode_cpu(text, raw_text, target_pids):
    """Consume real perf script blocks; stack success requires multiple resolved PCs."""
    samples, chains, current = [], [], None
    # perf's default sample header after the explicit -F fields. Threads print pid/tid.
    header = re.compile(r'^\s*.+?\s+(\d+)/(\d+)\s+(\d+\.\d+):\s+cpu-clock(?::[ukhS]+)?:')
    frame = re.compile(r'^\s*([0-9a-fA-F]+)\s+(.+?)\s+\((.*?)\)\s*$')
    for line in text.splitlines() + ['']:
        match = header.match(line)
        if match:
            if current:
                samples.append(current)
            current = dict(pid=int(match[1]), tid=int(match[2]), time_secs=match[3], frames=[])
            # Some versions print the sampled frame on the header; preserve it separately.
            suffix = line[match.end():].strip()
            inline = frame.match(suffix)
            if inline:
                current['frames'].append(dict(ip=inline[1], symbol=inline[2], dso=inline[3]))
        elif current and (match := frame.match(line)):
            current['frames'].append(dict(ip=match[1], symbol=match[2], dso=match[3]))
        elif not line.strip() and current:
            samples.append(current); current = None
    tids, depths = collections.Counter(), collections.Counter()
    unresolved = foreign = multi = 0
    folded = collections.Counter()
    for sample in samples:
        if sample['pid'] not in target_pids:
            foreign += 1
            continue
        tids[str(sample['tid'])] += 1
        frames = sample['frames']
        depths[str(len(frames))] += 1
        resolved = [f for f in frames if f['symbol'] not in ('[unknown]', '0x0') and f['dso'] != '[unknown]']
        unresolved += len(resolved) != len(frames) or not frames
        multi += len(resolved) >= 2
        folded[';'.join(f['symbol'] for f in reversed(frames)) or '[unresolved]'] += 1
        chains.append(sample)
    lost = len(re.findall(r'PERF_RECORD_LOST(?:_SAMPLES)?\b', raw_text))
    throttle = len(re.findall(r'PERF_RECORD_THROTTLE\b', raw_text))
    unthrottle = len(re.findall(r'PERF_RECORD_UNTHROTTLE\b', raw_text))
    raw_samples = len(re.findall(r'PERF_RECORD_SAMPLE\b', raw_text))
    return dict(samples=len(chains), per_tid=dict(tids), depth_distribution=dict(depths),
                multi_frame_samples=multi, unresolved_samples=unresolved, foreign_samples=foreign,
                raw_sample_records=raw_samples, lost_records=lost, throttle_records=throttle,
                unthrottle_records=unthrottle,
                task_records=len(re.findall(r'PERF_RECORD_(?:FORK|EXIT|COMM)\b', raw_text)),
                mmap_records=len(re.findall(r'PERF_RECORD_MMAP2?\b', raw_text)),
                callchains=chains, folded=dict(folded),
                complete=False, stack_useful=multi > 0,
                truncated_stack_fraction=None,
                truncation_reason='8192-byte dump and optimized-away/tail/async frames cannot prove complete unwinding')


def cpu_phases(chains, window):
    if not window.get('valid'):
        return dict(complete=False, reason='missing validated host clock')
    counts = collections.Counter()
    for sample in chains:
        whole, fraction = sample['time_secs'].split('.', 1)
        at = int(whole) * 1_000_000_000 + int(fraction[:9].ljust(9, '0'))
        lo, hi = window['start_bounds_ns']
        end_lo, end_hi = window['end_bounds_ns']
        phase = 'measurement' if hi <= at < end_lo else 'outside_measurement' if at < lo or at >= end_hi else 'boundary_uncertain'
        counts[phase] += 1
    return dict(complete=True, samples=dict(counts), exact_warmup_drain=False,
                uncertainty_ns=window.get('uncertainty_ns'))


def load_trace(path):
    try:
        result = json.loads(Path(path).read_text())
        if result.get('schema') != 1 or result.get('mode') not in ('none', 'syscalls', 'cpu'):
            raise ValueError('trace manifest schema')
        return result
    except (OSError, ValueError, AttributeError):
        return dict(complete=False, issues=['missing/malformed external trace manifest'])
