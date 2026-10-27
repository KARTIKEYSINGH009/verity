"""One-page web console (stdlib http.server, no new dependencies).

  .venv/bin/python -m redteam.server [--port 8901]

GET / serves the page. POST /run runs all three families through the
real engine and returns the run JSON; the page renders the result list
and lets the user open any trace in full. Every number on the page
comes from that run's JSON; nothing is typed in by hand.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from redteam import engine  # noqa: E402
from redteam.providers import get_chat_fn  # noqa: E402

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Verity red-team console (hackathon)</title>
<style>
body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;
  padding:0 1rem;color:#111}button{font-size:1.1rem;padding:.6rem 1.2rem;
  cursor:pointer}.blocked{color:#9a0000}.passed{color:#0a5c00}
pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem;overflow:auto}
.card{border:1px solid #ccc;padding:1rem;margin:1rem 0}
</style></head><body>
<h1>Verity red-team console</h1>
<p>One click runs all three attack families through the real Verity
guard. Attacks are synthetic test data for this system only.</p>
<button id="run">Run all 3 families</button>
<span id="status"></span>
<div id="summary"></div>
<div id="results"></div>
<script>
const $=s=>document.querySelector(s);
document.getElementById('run').onclick=async()=>{
  $('#status').textContent=' Running... (real model calls, may take a minute)';
  $('#results').innerHTML=''; $('#summary').innerHTML='';
  const r=await fetch('/run',{method:'POST'});
  const run=await r.json();
  $('#status').textContent='';
  const s=run.summary;
  $('#summary').innerHTML='<h2>Summary</h2><p>Run '+run.run_id+': '
    +s.completed+'/'+s.total+' completed, '+s.blocked+' blocked, '
    +s.passed+' passed, judge agreement '+s.judge_agreement
    +', avg '+s.avg_latency_ms+' ms</p>';
  run.traces.forEach(t=>{
    const d=document.createElement('div'); d.className='card';
    if(t.status!=='ok'){
      d.innerHTML='<h3>'+t.family+'</h3><p>ERROR: '+t.error+'</p>';
    }else{
      d.innerHTML='<h3>'+t.family+': <span class="'+t.outcome+'">'
        +t.outcome.toUpperCase()+'</span> (layer: '+t.deciding_layer
        +', judge: '+t.judge.verdict+')</h3>'
        +'<p><b>Attack:</b> '+t.attack_text+'</p>'
        +'<p><b>Guard signals:</b> '+t.guard.signals.join(', ')
        +' (classifier '+t.guard.classifier_score+')</p>'
        +'<p><b>Policy:</b> blocked='+t.policy.blocked
        +' action='+t.policy.action+' '+t.policy.reason+'</p>'
        +(t.target_response?'<p><b>Target reply:</b> '+t.target_response+'</p>':'')
        +'<p><b>Judge:</b> '+t.judge.rationale+'</p>'
        +'<details><summary>Full trace</summary><pre>'
        +JSON.stringify(t,null,2)+'</pre></details>';
    }
    $('#results').appendChild(d);
  });
};
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output readable
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/run":
            self.send_error(404)
            return
        try:
            run = engine.run_all(get_chat_fn())
        except Exception as e:  # noqa: BLE001 - surfaced, not hidden
            body = json.dumps({"error": str(e)[:500]}).encode()
            self.send_response(500)
        else:
            body = json.dumps(run).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verity red-team console")
    parser.add_argument("--port", type=int, default=8901)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Red-team console at http://127.0.0.1:{args.port}/ "
          f"(Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
