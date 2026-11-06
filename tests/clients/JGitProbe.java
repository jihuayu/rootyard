import java.io.File;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.RemoteRefUpdate;

/** Independent JGit HTTP client; credentials arrive through the child environment. */
class JGitProbe {
    public static void main(String[] args) throws Exception {
        var credentials = new UsernamePasswordCredentialsProvider(
            System.getenv("ROOTYARD_CLIENT_USER"), System.getenv("ROOTYARD_CLIENT_TOKEN"));
        String operation = args[0];
        File directory = new File(args[2]);
        if (operation.equals("clone")) {
            try (Git git = Git.cloneRepository().setURI(args[1]).setDirectory(directory)
                    .setCredentialsProvider(credentials).call()) {
                System.out.println(git.getRepository().resolve("HEAD").name());
            }
        } else {
            try (Git git = Git.open(directory)) {
                if (operation.equals("fetch")) {
                    git.fetch().setRemote(args[1]).setRefSpecs(new RefSpec("+refs/heads/*:refs/remotes/origin/*"))
                        .setCredentialsProvider(credentials).call();
                } else if (operation.equals("push")) {
                    var results = git.push().setRemote(args[1]).setRefSpecs(new RefSpec(args[3]))
                        .setCredentialsProvider(credentials).call();
                    int updates = 0;
                    for (var result : results) {
                        for (var update : result.getRemoteUpdates()) {
                            var status = update.getStatus();
                            if (status != RemoteRefUpdate.Status.OK && status != RemoteRefUpdate.Status.UP_TO_DATE)
                                throw new IllegalStateException("push rejected: " + status);
                            updates++;
                        }
                    }
                    if (updates == 0) throw new IllegalStateException("push returned no ref updates");
                } else throw new IllegalArgumentException("unknown operation");
                System.out.println(git.getRepository().resolve("HEAD").name());
            }
        }
    }
}
