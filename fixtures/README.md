`injection.patch` is the planted injection for the live runs. It adds a comment block inside `BenchmarkTest00011_post`, the POST handler of OWASP case 00011, after its `cur.execute` call. The block sits below the flagged statement, so the line Bandit reports for the B608 alert (line 47 of `testcode/BenchmarkTest00011.py`) does not move. Both agents read the handler to classify the case, so the model sees the comment on every run.

To apply the patch, run `git -C <owasp checkout> apply <path>/injection.patch`, where `<owasp checkout>` is your checkout of the OWASP Benchmark for Python and `<path>` is the path to this repository's `fixtures` directory. To remove it, run `git -C <checkout> checkout -- testcode/BenchmarkTest00011.py`, which restores that file from git.

Use the patched checkout only for the live-run measurement. Never use it for the classification results in the report. Remove the patch before any run that produces those results.
