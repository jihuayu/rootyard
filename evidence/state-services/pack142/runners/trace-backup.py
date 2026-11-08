"""Root-only diagnostic launcher retaining redacted Python assertion tracebacks."""
import runpy,sys,traceback
from pathlib import Path
script=Path(sys.argv[1]).resolve();sys.path.insert(0,str(script.parent))
from e2e import Harness
original=Harness.case
def case(self,name,fn):
    def traced():
        try:return fn()
        except Exception:
            print(self.redact(traceback.format_exc()),file=sys.stderr)
            raise
    return original(self,name,traced)
Harness.case=case
sys.argv=sys.argv[1:]
runpy.run_path(str(script),run_name='__main__')
