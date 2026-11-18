"""Bounded, byte-transparent loopback fixture for the Redis wake partition."""
from dataclasses import dataclass
import select
import socket
import threading


@dataclass(frozen=True)
class RelayCounts:
    forwarded: int
    refused: int
    active: int


class RedisPartitionRelay:
    socket_timeout = 0.25
    max_connections = 8

    def __init__(self, redis_port):
        self.target = ("127.0.0.1", redis_port)
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.partitioned = False
        self.failed = False
        self.forwarded = self.refused = 0
        self.sessions = {}
        self.listener = socket.socket()
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(self.max_connections)
            self.listener.settimeout(self.socket_timeout)
            self.port = self.listener.getsockname()[1]
            self.acceptor = threading.Thread(target=self.accept, daemon=True)
            self.acceptor.start()
        except BaseException:
            self.listener.close()
            raise

    def accept(self):
        try:
            while not self.stopped.is_set():
                try:
                    client, _ = self.listener.accept()
                except TimeoutError:
                    continue
                self.route(client)
        except Exception:
            if not self.stopped.is_set():
                self.failed = True

    def route(self, client):
        with self.lock:
            if self.partitioned or self.stopped.is_set():
                self.refused += 1
                client.close()
                return
            upstream = None
            try:
                assert len(self.sessions) < self.max_connections
                upstream = socket.create_connection(self.target, timeout=self.socket_timeout)
                client.settimeout(self.socket_timeout)
                thread = threading.Thread(target=self.pump, args=(client, upstream), daemon=True)
                self.sessions[thread] = (client, upstream)
                try:
                    thread.start()
                except BaseException:
                    del self.sessions[thread]
                    raise
                self.forwarded += 1
            except BaseException:
                client.close()
                if upstream is not None:
                    upstream.close()
                raise

    def pump(self, client, upstream):
        try:
            while not self.stopped.is_set():
                ready, _, _ = select.select((client, upstream), (), (), self.socket_timeout)
                for source in ready:
                    data = source.recv(16384)
                    if not data:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(data)
        except (OSError, ValueError):
            pass
        except Exception:
            self.failed = True
        finally:
            with self.lock:
                client.close()
                upstream.close()
                del self.sessions[threading.current_thread()]

    def counts(self):
        with self.lock:
            assert not self.failed, "Owned relay failed"
            return RelayCounts(self.forwarded, self.refused, len(self.sessions))

    def cut(self):
        with self.lock:
            self.partitioned = True
            threads = list(self.sessions)
            for pair in self.sessions.values():
                for stream in pair:
                    try:
                        stream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    stream.close()
        for thread in threads:
            thread.join(timeout=1)
        assert all(not thread.is_alive() for thread in threads), "Owned relay sockets did not close"
        return len(threads)

    def heal(self):
        with self.lock:
            assert self.partitioned and not self.sessions and not self.stopped.is_set()
            self.partitioned = False

    def close(self):
        self.stopped.set()
        self.listener.close()
        try:
            self.cut()
        finally:
            self.acceptor.join(timeout=1)
        assert not self.acceptor.is_alive(), "Owned relay listener did not exit"
