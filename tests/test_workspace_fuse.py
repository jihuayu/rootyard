"""Actual kernel FUSE mount: transparent read, mmap, CoW write and rename."""
import mmap
import os
import sys
import concurrent.futures
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


class FuseMountTest(unittest.TestCase):
    def test_moved_symlink_cannot_escape_mount(self):
        if os.environ.get("ROOTYARD_FUSE_USERNS") != "1":
            env=dict(os.environ,ROOTYARD_FUSE_USERNS="1")
            child=subprocess.run(["unshare","-Urnm",sys.executable,"-m","unittest",
                "tests.test_workspace_fuse.FuseMountTest.test_moved_symlink_cannot_escape_mount"],
                env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(child.returncode,0,child.stdout+child.stderr)
            return
        binary=Path("target/debug/rootyard-vfs-mount").resolve()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-fuse-escape-") as root:
            root=Path(root);lower=root/"lower";upper=root/"upper";mount=root/"mount"
            lower.mkdir();upper.mkdir();mount.mkdir()
            (lower/"nested").mkdir()
            (lower/"nested/up").symlink_to("..")
            (lower/"nested/special").symlink_to(".rootyard-whiteouts.json")
            (lower/"nested/data.txt").write_text("safe")
            proc=subprocess.Popen([str(binary),str(lower),str(upper),str(mount)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not os.path.ismount(mount):
                    if proc.poll() is not None: self.fail(proc.stderr.read().decode())
                    time.sleep(.05)
                self.assertTrue(os.path.ismount(mount))
                self.assertEqual((mount/"nested/up/nested/data.txt").read_text(),"safe")
                with self.assertRaises(PermissionError):
                    (mount/"nested/up").rename(mount/"up")
                self.assertFalse((root/"escaped.txt").exists())
                self.assertFalse((mount/"up").exists())
                self.assertEqual(os.readlink(mount/"nested/up"),"..")
                with self.assertRaises(OSError):
                    (mount/"nested/special").rename(mount/".rootyard-whiteouts.tmp")
                self.assertFalse((upper/".rootyard-whiteouts.tmp").exists())
                (mount/"nested").rename(mount/"moved")
                self.assertEqual((mount/"moved/data.txt").read_text(),"safe")
                self.assertEqual((lower/"nested/data.txt").read_text(),"safe")
                self.assertTrue((upper/".rootyard-whiteouts.json").is_file())
                self.assertFalse((upper/".rootyard-whiteouts.json").is_symlink())
            finally:
                if os.path.ismount(mount): subprocess.run(["fusermount3","-u",str(mount)],check=True,timeout=10)
                proc.wait(timeout=10)
            proc=subprocess.Popen([str(binary),str(lower),str(upper),str(mount)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not os.path.ismount(mount):
                    if proc.poll() is not None: self.fail(proc.stderr.read().decode())
                    time.sleep(.05)
                self.assertEqual((mount/"moved/data.txt").read_text(),"safe")
                self.assertFalse((mount/"nested").exists())
                self.assertFalse((upper/".rootyard-whiteouts.json").is_symlink())
            finally:
                if os.path.ismount(mount): subprocess.run(["fusermount3","-u",str(mount)],check=True,timeout=10)
                proc.wait(timeout=10)

    def test_kernel_fuse_transparent_cow(self):
        if os.environ.get("ROOTYARD_FUSE_USERNS") != "1":
            env=dict(os.environ,ROOTYARD_FUSE_USERNS="1")
            child=subprocess.run(["unshare","-Urnm",sys.executable,"-m","unittest",
                "tests.test_workspace_fuse.FuseMountTest.test_kernel_fuse_transparent_cow"],
                env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(child.returncode,0,child.stdout+child.stderr)
            return
        binary=Path("target/debug/rootyard-vfs-mount").resolve()
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix="rootyard-fuse-") as root:
            root=Path(root);lower=root/"lower";upper=root/"upper";mount=root/"mount"
            lower.mkdir();upper.mkdir();mount.mkdir()
            (lower/"nested").mkdir()
            original=b"immutable baseline\n"*1000
            (lower/"nested/data.txt").write_bytes(original)
            proc=subprocess.Popen([str(binary),str(lower),str(upper),str(mount)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not os.path.ismount(mount):
                    if proc.poll() is not None: self.fail(proc.stderr.read().decode())
                    time.sleep(.05)
                self.assertTrue(os.path.ismount(mount),"kernel FUSE mount did not become active")
                path=mount/"nested/data.txt"
                self.assertFalse((upper/"nested/data.txt").exists())
                self.assertEqual(path.read_bytes(),original)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                    self.assertTrue(all(data==original for data in workers.map(lambda _:path.read_bytes(),range(16))))
                with path.open("rb") as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as mapped:
                    self.assertEqual(mapped[:],original)
                path.write_bytes(b"agent edit\n")
                self.assertEqual(path.read_bytes(),b"agent edit\n")
                self.assertEqual((lower/"nested/data.txt").read_bytes(),original)
                self.assertEqual((upper/"nested/data.txt").read_bytes(),b"agent edit\n")
                path.rename(mount/"renamed.txt")
                try: os.stat(mount/"renamed.txt")
                except OSError as error:
                    upper_list=list(upper.rglob('*')); mount_list=list(mount.iterdir())
                    proc.terminate(); proc.wait(timeout=5)
                    self.fail(f"stat={error} upper={upper_list} mount={mount_list} server={proc.stderr.read().decode()}")
                self.assertEqual((mount/"renamed.txt").read_bytes(),b"agent edit\n")
                self.assertFalse(path.exists())
                self.assertEqual((lower/"nested/data.txt").read_bytes(),original)
            finally:
                if os.path.ismount(mount): subprocess.run(["fusermount3","-u",str(mount)],check=True,timeout=10)
                proc.wait(timeout=10)
            proc=subprocess.Popen([str(binary),str(lower),str(upper),str(mount)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not os.path.ismount(mount):
                    if proc.poll() is not None: self.fail(proc.stderr.read().decode())
                    time.sleep(.05)
                self.assertEqual((mount/"renamed.txt").read_bytes(),b"agent edit\n")
                self.assertFalse((mount/"nested/data.txt").exists())
            finally:
                if os.path.ismount(mount): subprocess.run(["fusermount3","-u",str(mount)],check=True,timeout=10)
                proc.wait(timeout=10)


if __name__=="__main__": unittest.main()
