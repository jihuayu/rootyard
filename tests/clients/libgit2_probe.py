"""Invoke libgit2, independently of stock Git transport."""
import os
import sys
import pygit2

operation, remote, directory, *extra = sys.argv[1:]


class Callbacks(pygit2.RemoteCallbacks):
    def push_update_reference(self, refname, message):
        if message:
            raise RuntimeError("server rejected ref update: " + message)


callbacks = Callbacks(credentials=pygit2.UserPass(
    os.environ["ROOTYARD_CLIENT_USER"], os.environ["ROOTYARD_CLIENT_TOKEN"]))
if operation == "clone":
    repo = pygit2.clone_repository(remote, directory, callbacks=callbacks)
else:
    repo = pygit2.Repository(directory)
    transport = repo.remotes.create_anonymous(remote)
    if operation == "fetch":
        transport.fetch(["+refs/heads/*:refs/remotes/origin/*"], callbacks=callbacks)
    elif operation == "push":
        transport.push([extra[0]], callbacks=callbacks)
    else:
        raise ValueError("unknown operation")
print(repo.head.target)
