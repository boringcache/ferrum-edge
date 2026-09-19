"""Hosted-only synthetic IPv4 traffic. Stdout contains metadata, never data buffers."""

import argparse
import ctypes
import errno
import hashlib
import json
import mmap
import signal
import os
import select
import socket
import struct
import time

UDP_SEGMENT, UDP_GRO, SO_COOKIE, CBPF = 103, 104, 57, 51
UNAVAILABLE = {errno.ENOPROTOOPT, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES}
LIBC = ctypes.CDLL(None, use_errno=True)


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class MSG(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint),
                ("iov", ctypes.POINTER(IOV)), ("iovlen", ctypes.c_size_t),
                ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]


class MMSG(ctypes.Structure):
    _fields_ = [("msg", MSG), ("length", ctypes.c_uint)]


class Fixture:
    def __init__(self, mode):
        self.report = {"mode": mode, "status": "supported", "operations": [],
                       "sockets": [], "pid": os.getpid(), "uid": os.getuid(),
                       "netns": os.stat("/proc/self/ns/net").st_ino,
                       "boot_id": open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip(),
                       "start_ns": time.monotonic_ns()}
        self.report["start_ticks"] = open("/proc/self/stat", encoding="ascii").read().rsplit(")", 1)[1].split()[19]
        self.report["privileges"] = [line.strip() for line in open("/proc/self/status", encoding="ascii")
                                     if line.startswith(("Cap", "NoNewPrivs:", "Seccomp:"))]
        assert os.getuid() == 65534, "fixture must run at the declared unprivileged UID"
        for line in self.report["privileges"]:
            name, value = line.split(":", 1)
            if name.startswith("Cap"):
                assert int(value.strip(), 16) == 0, "fixture capability set must be empty"
            if name == "NoNewPrivs":
                assert value.strip() == "1", "fixture requires no_new_privs"
        self.generations = {}
        self.live = []

    def note(self, op, **fields):
        assert len(self.report["operations"]) < 128
        self.report["operations"].append({"op": op, "at_ns": time.monotonic_ns(), **fields})

    def identify(self, s, role):
        cookie = struct.unpack("=Q", s.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))[0]
        fd = s.fileno()
        gen = self.generations.get(fd, 0) + 1
        self.generations[fd] = gen
        self.report["sockets"].append({"role": role, "cookie": cookie, "fd": fd,
                                       "fd_generation": gen, "opened_ns": time.monotonic_ns()})
        return cookie

    def sock(self, role, reuse=False, address=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.live.append(s)
        s.settimeout(1)
        # Do not seed the cookie. The first tracing helper must assign it.
        fd = s.fileno()
        gen = self.generations.get(fd, 0) + 1
        self.generations[fd] = gen
        self.report["sockets"].append({"role": role, "cookie": None, "fd": fd,
            "fd_generation": gen, "opened_ns": time.monotonic_ns(), "preassigned_cookie": False})
        if reuse:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(address or ("127.0.0.1", 0))
        return s

    def close(self, s):
        fd = s.fileno()
        generation = self.generations[fd]
        cookie = struct.unpack("=Q", s.getsockopt(1, SO_COOKIE, 8))[0]
        for entry in self.report["sockets"]:
            if entry["fd"] == fd and entry["fd_generation"] == generation:
                assert entry["cookie"] in (None, cookie), "cookie changed during socket lifetime"
                entry["cookie"] = cookie
        s.close()
        self.note("close", fd=fd, fd_generation=generation, cookie=cookie)
        for entry in self.report["sockets"]:
            if entry["fd"] == fd and entry["fd_generation"] == generation:
                entry["closed_ns"] = time.monotonic_ns()

    def recv(self, s, size=8192, control=64, flags=0):
        try:
            payload, ancillary, returned_flags, _ = s.recvmsg(size, control, flags)
        except OSError as error:
            self.note("recvmsg", errno=error.errno)
            raise
        segments = [struct.unpack("=i", value)[0] for level, kind, value in ancillary
                    if level == socket.IPPROTO_UDP and kind == UDP_GRO and len(value) == 4]
        self.note("recvmsg", length=len(payload), segments=segments, flags=returned_flags,
                  requested_flags=flags)
        return len(payload), segments, returned_flags

    def pair(self):
        receiver = self.sock("receiver")
        receiver.setsockopt(socket.IPPROTO_UDP, UDP_GRO, 1)
        sender = self.sock("sender")
        sender.connect(receiver.getsockname())
        self.note("option", option="UDP_GRO", success=True)
        return sender, receiver

    def offload(self):
        sender, receiver = self.pair()
        sender.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, 1024)
        self.note("option", option="UDP_SEGMENT", segment=1024, success=True)
        n = sender.sendmsg([bytes(4096)])
        self.note("sendmsg", length=4096, returned=n, effective_segment=1024, source="socket")
        assert n == 4096
        length, segments, flags = self.recv(receiver)
        if not (length == 4096 and segments == [1024] and flags == 0):
            self.report.update(status="unsupported", reason="loopback_did_not_return_multisegment_GRO")
            return
        for length, segment in [(2048, 512), (256, 0)]:
            n = sender.sendmsg([bytes(length)], [(17, UDP_SEGMENT, struct.pack("=H", segment))])
            self.note("sendmsg", length=length, returned=n, effective_segment=segment, source="u16_cmsg")
            got, strides, flags = self.recv(receiver)
            assert n == length and got == length and flags == 0
            assert strides == ([segment] if segment else [])
        # Deliberately malformed TX cmsg: four bytes is NOT the u16 ABI.
        try:
            sender.sendmsg([bytes(512)], [(17, UDP_SEGMENT, struct.pack("=I", 256))])
        except OSError as error:
            self.note("sendmsg_invalid_u32", errno=error.errno)
            assert error.errno == errno.EINVAL
        else:
            raise AssertionError("TX UDP_SEGMENT unexpectedly accepted u32")
        sender.sendmsg([bytes(2048)])
        _, _, flags = self.recv(receiver, size=16)
        assert flags & socket.MSG_TRUNC
        sender.sendmsg([bytes(2048)])
        _, _, flags = self.recv(receiver, control=0)
        assert flags & socket.MSG_CTRUNC
        sender.sendmsg([bytes(2048)])
        self.recv(receiver, flags=socket.MSG_PEEK)
        self.recv(receiver)
        # This reaches recvmsg and returns EAGAIN (not a Python select timeout).
        receiver.setblocking(False)
        try:
            self.recv(receiver)
        except BlockingIOError as error:
            assert error.errno == errno.EAGAIN
        else:
            raise AssertionError("empty receiver unexpectedly returned data")
        receiver.settimeout(1)
        # Shared descriptor: identical cookie; FD reuse: a new cookie/generation.
        alias = socket.socket(fileno=os.dup(sender.fileno()))
        self.live.append(alias)
        old_cookie = struct.unpack("=Q", sender.getsockopt(1, SO_COOKIE, 8))[0]
        self.report["sockets"][1]["cookie"] = old_cookie
        assert self.identify(alias, "sender_alias") == old_cookie
        sender_fd = sender.fileno()
        self.close(sender)
        alias.sendmsg([bytes(2048)])
        self.recv(receiver)
        self.close(alias)
        replacement = self.sock("sender_reused_fd")
        assert replacement.fileno() == sender_fd
        replacement.connect(receiver.getsockname())
        replacement.sendmsg([bytes(256)])
        self.recv(receiver)
        new_cookie = struct.unpack("=Q", replacement.getsockopt(1, SO_COOKIE, 8))[0]
        assert new_cookie != old_cookie
        self.report["sockets"][-1]["cookie"] = new_cookie

    def classic(self, fallback):
        first = self.sock("group_0", reuse=True)
        second = self.sock("group_1", reuse=True, address=first.getsockname())
        selected = 42 if fallback else 1
        instruction = Filter(0x06, 0, 0, selected)  # classic BPF_RET | BPF_K
        program = Program(1, ctypes.pointer(instruction))
        result = LIBC.setsockopt(first.fileno(), socket.SOL_SOCKET, CBPF,
                                 ctypes.byref(program), ctypes.sizeof(program))
        if result:
            raise OSError(ctypes.get_errno(), "classic attach")
        self.note("SO_ATTACH_REUSEPORT_CBPF", returned=0, group_generation=1,
                  classic_sha256=hashlib.sha256(bytes(instruction)).hexdigest(),
                  disposition="invalid_index_fallback" if fallback else "select_slot_1")
        sender = self.sock("sender")
        # Connected stable flow: kernel fallback is allowed to choose either socket.
        sender.connect(first.getsockname())
        sender.sendmsg([bytes(128)])
        readable, _, _ = select.select([first, second], [], [], 1)
        assert len(readable) == 1
        chosen = readable[0]
        assert fallback or chosen is second
        assert self.recv(chosen)[0] == 128
        self.note("selection", selected_cookie=struct.unpack("=Q", chosen.getsockopt(1, SO_COOKIE, 8))[0],
                  group_generation=1)
        if fallback: return
        replacement = Filter(0x06, 0, 0, 0)
        changed = Program(1, ctypes.pointer(replacement))
        assert LIBC.setsockopt(second.fileno(), socket.SOL_SOCKET, CBPF,
                              ctypes.byref(changed), ctypes.sizeof(changed)) == 0
        self.note("SO_ATTACH_REUSEPORT_CBPF_replace", returned=0, group_generation=2,
                  classic_sha256=hashlib.sha256(bytes(replacement)).hexdigest())
        sender.sendmsg([bytes(128)])
        readable, _, _ = select.select([first, second], [], [], 1)
        assert readable == [first] and self.recv(first)[0] == 128
        # Linux SO_DETACH_REUSEPORT_BPF=68; detach is distinct from socket close.
        zero = ctypes.c_int(0)
        assert LIBC.setsockopt(first.fileno(), socket.SOL_SOCKET, 68,
                              ctypes.byref(zero), ctypes.sizeof(zero)) == 0
        self.note("SO_DETACH_REUSEPORT_BPF", returned=0)

    def batches(self):
        sender, receiver = self.pair()
        sender.setsockopt(17, UDP_SEGMENT, 512)
        data = ctypes.create_string_buffer(2048)
        vector = IOV(ctypes.cast(data, ctypes.c_void_p), 2048)
        # First message valid, second malformed u32 UDP_SEGMENT => partial batch 1/2.
        invalid = ctypes.create_string_buffer(struct.pack("=QiiI4x", 20, 17, UDP_SEGMENT, 512))
        batch = (MMSG * 2)()
        for entry in batch:
            entry.msg.iov = ctypes.pointer(vector)
            entry.msg.iovlen = 1
        batch[1].msg.control = ctypes.cast(invalid, ctypes.c_void_p)
        batch[1].msg.controllen = 24
        result = LIBC.sendmmsg(sender.fileno(), batch, 2, 0)
        self.note("sendmmsg", requested=2, returned=result, first_length=batch[0].length,
                  errno=ctypes.get_errno() if result < 0 else None)
        assert result == 1 and batch[0].length == 2048
        control = ctypes.create_string_buffer(64)
        receive = (MMSG * 2)()
        for entry in receive:
            entry.msg.iov = ctypes.pointer(vector)
            entry.msg.iovlen = 1
            entry.msg.control = ctypes.cast(control, ctypes.c_void_p)
            entry.msg.controllen = 64
        result = LIBC.recvmmsg(receiver.fileno(), receive, 2, socket.MSG_DONTWAIT, None)
        self.note("recvmmsg", requested=2, returned=result, first_length=receive[0].length,
                  flags=receive[0].msg.flags, observer_disposition="returned_prefix_only")
        assert result == 1 and receive[0].length == 2048

    def recvmmsg_cases(self):
        sender, receiver = self.pair()
        receiver.setblocking(False)
        sender.setsockopt(17, UDP_SEGMENT, 512)
        data = [ctypes.create_string_buffer(8192) for _ in range(32)]
        controls = [ctypes.create_string_buffer(64) for _ in range(32)]
        vectors = [IOV(ctypes.cast(d, ctypes.c_void_p), 8192) for d in data]

        def batch(count=32):
            array = (MMSG * count)()
            for i, entry in enumerate(array):
                entry.msg.iov = ctypes.pointer(vectors[i])
                entry.msg.iovlen = 1
                entry.msg.control = ctypes.cast(controls[i], ctypes.c_void_p)
                entry.msg.controllen = 64
            return array

        def receive(name, array, flags=socket.MSG_DONTWAIT, timeout=None, fd=None):
            ctypes.set_errno(0)
            result = LIBC.recvmmsg(receiver.fileno() if fd is None else fd,
                                  array, len(array), flags, timeout)
            self.note(name, requested=len(array), returned=result,
                      errno=ctypes.get_errno() if result < 0 else None,
                      messages=[{"length": array[i].length, "flags": array[i].msg.flags}
                                for i in range(max(0, result))])
            return result

        sender.sendmsg([bytes(2048)])
        sender.sendmsg([bytes(128)], [(17, UDP_SEGMENT, struct.pack("=H", 0))])
        assert receive("recvmmsg_mixed_prefix_32", batch()) == 2
        assert receive("recvmmsg_eagain", batch()) == -1 and ctypes.get_errno() == errno.EAGAIN
        assert receive("recvmmsg_ebadf", batch(), fd=-1) == -1 and ctypes.get_errno() == errno.EBADF
        sender.sendmsg([b""], [(17, UDP_SEGMENT, struct.pack("=H", 0))])
        assert receive("recvmmsg_zero_datagram", batch(1)) == 1
        sender.sendmsg([bytes(2048)])
        assert receive("recvmmsg_peek", batch(1), socket.MSG_PEEK | socket.MSG_DONTWAIT) == 1
        assert receive("recvmmsg_consume", batch(1)) == 1
        for name, size, capacity in [("data_trunc", 16, 64), ("control_trunc", 8192, 0)]:
            sender.sendmsg([bytes(2048)])
            array = batch(1)
            vectors[0].length = size
            array[0].msg.controllen = capacity
            assert receive("recvmmsg_" + name, array) == 1
            assert array[0].msg.flags & (socket.MSG_TRUNC if size == 16 else socket.MSG_CTRUNC)
            vectors[0].length = 8192
        receiver.setblocking(True)
        sender.sendmsg([bytes(2048)])
        assert receive("recvmmsg_waitforone", batch(), 0x10000) == 1
        signal.signal(signal.SIGALRM, lambda *_: None)
        signal.setitimer(signal.ITIMER_REAL, 0.05)
        try:
            assert receive("recvmmsg_eintr", batch(1), 0) == -1 and ctypes.get_errno() == errno.EINTR
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        receiver.setblocking(False)
        # Actual protected memory: readable input header, failed output writes.
        # Separate slots ensure a bad later slot does not erase an earlier prefix.
        page = mmap.PAGESIZE
        for fault in ("header", "control", "sockaddr", "flags", "controllen", "msg_len", "prefix", "timeout"):
            memory = mmap.mmap(-1, page * 2, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            base = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            array = batch(2 if fault == "prefix" else 1)
            timeout = None
            if fault == "header":
                pointer = ctypes.cast(base + page, ctypes.POINTER(MMSG))
                assert LIBC.mprotect(ctypes.c_void_p(base + page), page, 0) == 0
            elif fault in ("flags", "controllen", "msg_len"):
                # Only the named output field crosses into a read-only page.
                offset = {"flags": 48, "controllen": 40, "msg_len": 56}[fault]
                pointer = ctypes.cast(base + page - offset, ctypes.POINTER(MMSG))
                ctypes.memmove(pointer, array, ctypes.sizeof(MMSG))
                assert LIBC.mprotect(ctypes.c_void_p(base + page), page, mmap.PROT_READ) == 0
            else:
                pointer = array
                if fault == "control":
                    array[0].msg.control = base + page
                    assert LIBC.mprotect(ctypes.c_void_p(base + page), page, mmap.PROT_READ) == 0
                if fault in ("sockaddr", "prefix"):
                    array[-1].msg.name = 1
                    array[-1].msg.namelen = 16
                if fault == "timeout":
                    ctypes.memmove(base + page, struct.pack("=qq", 1, 0), 16)
                    timeout = ctypes.c_void_p(base + page)
                    assert LIBC.mprotect(ctypes.c_void_p(base + page), page, mmap.PROT_READ) == 0
            sender.sendmsg([bytes(2048)])
            if fault == "prefix": sender.sendmsg([bytes(2048)])
            ctypes.set_errno(0)
            result = LIBC.recvmmsg(receiver.fileno(), pointer, len(array), socket.MSG_DONTWAIT, timeout)
            error = ctypes.get_errno() if result < 0 else None
            self.note("recvmmsg_copyout_" + fault, returned=result, errno=error, requested=len(array),
                      flags=array[0].msg.flags, controllen=array[0].msg.controllen)
            if fault == "prefix": assert result == 1
            elif fault == "control":
                # Linux may return success + CTRUNC for inaccessible ancillary storage.
                assert (result == -1 and error == errno.EFAULT) or (result == 1 and (array[0].msg.flags & socket.MSG_CTRUNC or array[0].msg.controllen == 0))
            else: assert result == -1 and error == errno.EFAULT
            assert LIBC.mprotect(ctypes.c_void_p(base + page), page, mmap.PROT_READ | mmap.PROT_WRITE) == 0
            memory.close()
            # A fault before UDP consumption can leave its datagram queued.
            while receive("recvmmsg_fault_cleanup", batch(1)) > 0: pass

    def read_failure(self):
        sender, receiver = self.pair()
        sender.setsockopt(17, UDP_SEGMENT, 512)
        sender.sendmsg([bytes(2048)])
        result = LIBC.recvmsg(receiver.fileno(), ctypes.c_void_p(1), socket.MSG_DONTWAIT)
        self.note("recvmsg_unreadable_header", returned=result, errno=ctypes.get_errno())
        assert result == -1 and ctypes.get_errno() == errno.EFAULT
        data = ctypes.create_string_buffer(4096)
        vector = IOV(ctypes.cast(data, ctypes.c_void_p), 4096)
        control = ctypes.create_string_buffer(64)
        # Valid ancillary copy, then failing sockaddr copyout: a kernel UDP return
        # alone would falsely accept this receive. The outer syscall must succeed.
        msg = MSG(name=1, namelen=16, iov=ctypes.pointer(vector), iovlen=1,
                  control=ctypes.cast(control, ctypes.c_void_p), controllen=64)
        result = LIBC.recvmsg(receiver.fileno(), ctypes.byref(msg), socket.MSG_DONTWAIT)
        self.note("recvmsg_failed_copyout", returned=result, errno=ctypes.get_errno())
        assert result == -1 and ctypes.get_errno() == errno.EFAULT

    def verify_diag_cookies(self):
        # This runs AFTER observed operations. Neither SO_COOKIE nor sock-diag
        # seeds a fixture socket before the tracing helper sees its first use.
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as diag:
            diag.settimeout(1)
            request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_UDP, 0, 0, 0xFFFFFFFF)
            request += bytes(40) + struct.pack("=II", 0xFFFFFFFF, 0xFFFFFFFF)
            diag.sendto(struct.pack("=IHHII", 16 + len(request), 20, 0x301, 1, 0) + request, (0, 0))
            cookies, done = {}, False
            while not done:
                data, _, flags, _ = diag.recvmsg(1048576)
                assert not flags & socket.MSG_TRUNC
                offset = 0
                while offset + 16 <= len(data):
                    length, kind, flags, seq, _ = struct.unpack_from("=IHHII", data, offset)
                    assert length >= 16 and offset + length <= len(data) and seq == 1
                    assert not flags & 0x10
                    body = data[offset + 16:offset + length]
                    if kind == 3: done = True
                    elif kind == 2: raise AssertionError("sock-diag rejected cookie verification")
                    elif kind == 20:
                        assert len(body) >= 72
                        low, high = struct.unpack_from("=II", body, 44)
                        cookies[struct.unpack_from("=I", body, 68)[0]] = low | high << 32
                    offset += (length + 3) & ~3
        for s in self.live:
            if s.fileno() < 0: continue
            cookie = struct.unpack("=Q", s.getsockopt(1, SO_COOKIE, 8))[0]
            inode = int(os.readlink(f"/proc/self/fd/{s.fileno()}")[8:-1])
            assert cookies.get(inode) == cookie and cookie != 0
            self.note("cookie_verified_after_traffic", fd=s.fileno(), cookie=cookie,
                      diag_cookie=cookies[inode], no_preassignment=True)

    def run(self):
        try:
            if self.report["mode"] == "offload":
                self.offload()
            elif self.report["mode"] == "batches":
                self.batches()
            elif self.report["mode"] == "recvmmsg-cases":
                self.recvmmsg_cases()
            elif self.report["mode"] == "read-failure":
                self.read_failure()
            else:
                self.classic(self.report["mode"] == "classic-fallback")
            self.verify_diag_cookies()
        except OSError as error:
            self.report.update(status="unsupported" if error.errno in UNAVAILABLE else "error",
                               reason="fixture_socket_operation", errno=error.errno)
        except AssertionError as error:
            self.report.update(status="error", reason=str(error) or "fixture_assertion")
        finally:
            for s in self.live:
                if s.fileno() >= 0:
                    self.close(s)
            self.report["end_ns"] = time.monotonic_ns()
        print(json.dumps(self.report, sort_keys=True))
        return int(self.report["status"] == "error")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["offload", "batches", "read-failure", "classic-select", "classic-fallback", "recvmmsg-cases"])
    raise SystemExit(Fixture(parser.parse_args().mode).run())
