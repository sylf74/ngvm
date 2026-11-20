# Operator's manual (v0.28.2)

Day-to-day operation of a tenant deployed on Kubernetes (`NGVM_RUN_MODE: kubernetes`): where each
part runs, the usual actions, how to check the state, the known failures and their remedies,
upgrades. The installation of each part is in its own guide (table below); this manual does not
repeat it. The examples use the tenant `lab` (namespace `ngvm-lab`); replace it with yours.

| To install or change | Guide |
| --- | --- |
| GitLab groups, projects, variables, releases | [`deployment.md`](deployment.md) |
| The tenant on Kubernetes, the watch, the tenant's database | [`kubernetes.md`](kubernetes.md) |
| A collector near a network | [`collectors.md`](collectors.md) |
| SSH collection, OpenVAS, external scan | [`scanning.md`](scanning.md), [`openvas.md`](openvas.md) |
| Alerts, Word sheet, analysts' sign-in and review page | [`alerts.md`](alerts.md), [`alert-word.md`](alert-word.md), [`sign-in.md`](sign-in.md) |
| Chat, reporting database and Grafana, GTI | [`chat.md`](chat.md), [`reporting.md`](reporting.md), [`gti.md`](gti.md) |
| Remediation tickets, priorities and SLA | [`dispatch.md`](dispatch.md), [`sla.md`](sla.md) |
| The radar of the watch team, the shared intelligence service | [`radar.md`](radar.md) |

## 1. Where each part runs

| Part | Where | When | Started by |
| --- | --- | --- | --- |
| Internal scans: SSH (Trivy, dnf) and OpenVAS | Collector VM near the network (`ngvm-collector@<connector>`, Docker or Podman) | Its systemd timer (`connectors` of `docs/platform.md` §6, or `install-collector.sh --schedule`, default 07:30) | systemd |
| CMDB (iTop, read only, v0.19.0) | Connector `itop` of the collector (`ngvm-collector@<connector>`), source `cmdb` | Its systemd timer, before the daily run | systemd |
| External scan (OpenVAS from the internet) | Pipeline of the project `<tenant>-external`, on the runner of the cloud scanner (tag `scan-cloud`; deployed by `deploy/scanner` since v0.18.2) | Its pipeline schedule | GitLab |
| Daily run: collect → via → detect → assets → triage → publish, inventory, dispatch | CronJob `ngvm-<tenant>-daily` | `daily.schedule` (default 05:45, Europe/Paris; suspended with `NGVM_K8S_SUSPEND=true`) | Kubernetes |
| Watch | CronJob `ngvm-<tenant>-watch` | Every 10 minutes | Kubernetes |
| Detection, watch and decision services | Deployments `ngvm-<tenant>-detect`, `-via`, `-verdict` | Always | Kubernetes |
| Review page and sender | Deployments `ngvm-<tenant>-review` (oauth2-proxy), `-sender` | Always | Kubernetes |
| Chat | Deployments `ngvm-<tenant>-chat`, `-tools` | Always | Kubernetes |
| Remediation tickets and the page of the requests | Deployments `ngvm-<tenant>-dispatch`, `-dispatch-page`; the step `dispatch` of the daily run | Always; tickets at the end of each daily run | Kubernetes |
| Shared intelligence service (v0.22.0) | Deployment `ngvm-<team>-intel` of the watch team's tenant (`NGVM_INTEL_SERVE=true`) | Always; GTI search every 6 hours when enabled | Kubernetes |
| Radar (v0.22.0) | The watch of the watch team's tenant (`alerts.mode: radar`) | Every 10 minutes | Kubernetes |
| Tenant's database | CloudNativePG cluster `ngvm-<tenant>-db` (with `NGVM_DATABASE=true`) | Always | The operator |
| Reporting database and Grafana | The portal (`deploy/portal`) or a PostgreSQL of your own | Always | — |

**Order of the schedules.** The daily run reads the latest detection of each source, if it is not
older than the source's `max_age_hours` (30 by default). With the defaults the collectors push at
07:30 and the daily run starts at 05:45: each run takes the detections of the day before. For the
same day's, set the collector timers before the daily run, an OpenVAS scan early enough to end
before it (`sudo systemctl edit ngvm-collector@<connector>.timer`). The external scan likewise
runs before the daily run; one older than the profile's `external.max_age_days` is left out.

## 2. Usual actions

### Scan again, inside the network

On the collector VM:

```bash
systemctl list-timers 'ngvm-collector@*' --all
sudo systemctl start --no-block ngvm-collector@lan-ssh.service
sudo systemctl start --no-block ngvm-collector@lan-openvas.service
journalctl -fu ngvm-collector@lan-ssh.service
systemctl list-units 'ngvm-collector@*.service' --all
```

The connector names follow the `@` in the timer names. `--no-block` returns at once (an OpenVAS
scan can take hours); Ctrl-C leaves the journal without stopping the run. A finished run is
`inactive`; `failed` means read its journal (§4). Each detection accepted shows in the service:

```bash
kubectl -n ngvm-lab logs deploy/ngvm-lab-detect --tail=10
```

### Scan again, from the internet

In GitLab: project `<tenant>-external` > Build > Pipelines > Run pipeline on `main`. Its runner
must be online (Settings > CI/CD > Runners); a cloud scanner billed by the hour must be started
first. Nothing is started by hand on the scanner.

```bash
glab api "runners?tag_list=scan-cloud" | jq '.[] | {id, description, status}'
```

### Run the daily run now

```bash
kubectl -n ngvm-lab create job --from=cronjob/ngvm-lab-daily ngvm-lab-daily-manual-1101
kubectl -n ngvm-lab get pods -l job-name=ngvm-lab-daily-manual-1101 -w
kubectl -n ngvm-lab wait --for=condition=complete job/ngvm-lab-daily-manual-1101 --timeout=60m
```

The job name must be new (a date in it); delete an old job to reuse its name
(`kubectl -n ngvm-lab delete job <name>`). The steps run one after the other as init containers;
the pod ends `Completed`.

### Read the CronJobs, the jobs and the logs

```bash
kubectl -n ngvm-lab get cronjob
kubectl -n ngvm-lab describe cronjob ngvm-lab-daily
kubectl -n ngvm-lab get jobs --sort-by=.metadata.creationTimestamp
kubectl -n ngvm-lab logs job/ngvm-lab-daily-manual-1101 -c triage
kubectl -n ngvm-lab get pod <pod> -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" "}{.state.terminated.exitCode}{"\n"}{end}'
```

The last command gives the exit code of each step of a daily run: the first one not `0` is the one
to read (`-c <step>`). Exit code 3 is a warning (partial collection, a database unreachable): the
run goes on.

### The supervision page: where the run is (v0.26.2)

Each step of the daily chain says where it is, when it starts and when it ends: on the working
volume (`/data/progress`) and to the decision service, which keeps the last five runs. Two ways to
read it, both without a terminal:

- **the page**, at `/run` of the review page's host (`https://ngvm-lab.example.org/run`): the same
  sign-in and the same analyst groups as the alerts (`docs/sign-in.md`), and nothing more to deploy
  when the tenant already has the review page and the chat. It shows the chain in the order it runs,
  with the state of each step (running, done, partial, failed), its duration, what it wrote and the
  pod to read its log in; then, for each pillar, the numbers worth watching — new CVEs over 24 hours
  and those in KEV, alerts to review, assets and coverage, collectors late, decisions per level, what
  the LLM cost, tickets by state; then the services that run beside the chain, with the shared
  volume's filling. It refreshes itself every 30 seconds and holds no state of its own: the steps
  come from the decision service, each number from the service that owns it.
- **the chat**, `get_run_progress`: « où en est le run ? », « quelle étape a échoué ? », « le run de
  ce matin est-il fini ? » (`docs/chat.md`).

A step is never stopped by this: a push the decision service refuses prints a `WARN  progress:` line
in the step's log and the step goes on. So a step missing from the page is not a step that failed —
read its log. `daily.progress: false` in the tenant's values switches the records off; without a
decision service (`verdict.enabled: false`) they stay on the working volume only.

```bash
kubectl -n ngvm-lab logs job/ngvm-lab-daily-manual-1101 -c collect | grep progress
kubectl -n ngvm-lab port-forward deploy/ngvm-lab-tools 8080:8080
```

The second command gives the page at `http://127.0.0.1:8080/run` for a tenant without the review
page; whoever reaches that port sees it, so the NetworkPolicy lets only oauth2-proxy and the chat
reach it, as for the review page.

### The central page, and the triage decision by decision (v0.28.0)

At `/home` of the same host: one card for each page of the tenant — the run, the decisions, the
exposure paths, the alerts to review — with its state and its numbers, and the outside dashboards
the tenant links to: the chat (from its host) and the portal's Grafana on the reporting database
(`NGVM_GRAFANA_URL`, v0.28.1: one portal, so one address). An address that is not `https://…` is
left out, and the deployment log says so.

On `/run`, under the pillars, **the triage, decision by decision**: the SSVC tree (CISA Coordinator)
drawn as the run's decisions walked it — one column per decision point (Exploitation, Automatable,
Technical impact, Mission & well-being), then the SSVC outcome and the delivery decision; one box per
value with the decisions that took it and the time they cost, and between two columns a band as wide
as the decisions that went that way. Under it, the paths taken most, with the decisions of each that
are for review: when most decisions are for review, the path says which estimated input sends them
there. Then **where the triage time went**: the step, the decisions, the rationales; the LLM's
questions, those without an answer and the time spent waiting for them; per rationale outcome
(answered, from the cache, not in time, budget reached) the decisions and the time; the ten
decisions that cost most.

At `/decision`, a search by CVE, asset, text or decision (100 answers at most), and the page of one
decision: its path drawn over the run's tree, each input with the source of its value (an estimated
one marked), the SSVC outcome and how it became the delivery decision, why it is for review, its
rationale and what it cost. A box of the decision column of the run page opens the decisions of that
level. The same numbers are in `triage.csv` (`inputs_ms`, `decide_ms`, `llm_ms`, `llm`) and in the
triage step's log (`time:`, `slow:`); the decision service gives the tree with
`GET /v1/tenants/<t>/triage-graph` (read token).

How to read the times: `inputs_ms` is the CVE's SSVC inputs, paid by the first decision of the CVE
(an LLM estimate of Automatable and Technical impact is in it); `decide_ms` the decision on the
asset; `llm_ms` the rationale of the CVE and decision, asked once for all its assets (the tree
divides it among them). A run made before v0.28.0 carries no time: the tree is drawn, the times are
empty.

### Why an asset is exposed: the path, drawn (v0.26.3)

At `/exposure` of the same host, beside the run page. Without an asset it lists those of the latest
run, most ACT first, with the exposure of each and where that value comes from; `?asset=<id>`, or a
click on a name, draws the path the exposure rests on: the internet or a zone, the flow, the service,
the asset, each step with the source that saw it and the day. Under it, the ports the collection saw
on the asset, and the exposure gaps that concern it — where the client's declaration and the
observation differ.

Read it when a client disputes a priority (« pourquoi web01 est-il en ACT ? »): the path is the
proof the run kept, and an exposure marked `assumed` is the worst case taken for want of proof, not
a measure — a scan of the asset or a flow declared in the profile settles it (`docs/scanning.md`,
the profile's `zones` and `flows`). The chat gives the same thing in words with
`get_exposure_path`.

### Where the ways in meet: the chokepoints (v0.27.0)

At the top of the same page: the paths that lead to the assets carrying an ACT decision, drawn in
four columns — the way in, the client's zones, what answers on the asset, the assets — each link as
thick as the findings behind it, and under the drawing the chokepoints ranked by those findings. A
zone or a published endpoint that carries the way in to twelve assets is one ticket, not twelve, and
the number of findings behind it is what goes in that ticket. `?level=ATTEND` reads the same thing
for the level below.

The counts come from the run the decision service already holds (`GET /v1/tenants/<t>/exposure-graph`,
read token), computed in memory: no graph database and nothing more pushed. Two things to keep in
mind when reading it:

- it counts what the run **observed**; it never says a path is the only way in, so closing a
  chokepoint cuts the paths listed, not every path that may exist;
- the assets whose exposure is assumed have no path, so they are outside the drawing and counted
  apart (« Assets with no path »). A high number there means the graph is thin, not that the client
  is safe: scan those assets or declare their flows.

In the chat, `list_chokepoints` answers « par quoi commencer ? » with the same ranking.

### Following a way in, node by node (v0.27.2)

A client of a few hundred assets has a graph no page can draw whole: only the heaviest sixty nodes
are drawn, and the rest is counted. So the reading starts from the ranking rather than from the
picture: click the label of a chokepoint, or any box of the drawing, and the page comes back centred
on that node — what is within two hops of it either way, drawn whole, and the assets whose path goes
through it, named with the findings each carries. `?depth=1` tightens the view, `?depth=3` widens it;
an asset's box leads to its own path as before.

It is a link, not a script: the page is rendered by the server and the Content-Security-Policy of
the review page is unchanged.

Two things worth knowing:

- a node is named by the run that saw it, so a link kept from an earlier run may name a node this
  run no longer observes. The page says so (« node not in the latest run ») rather than drawing an
  empty graph: go back to the whole picture and start again from the ranking;
- the assets listed behind a node are those carrying a finding at the level being read. A node whose
  list is empty at ACT may well carry ATTEND findings: `?level=ATTEND` on the whole picture first.

### What the LLM cost, and whether it is worth it (v0.23.7)

The triage step ends with one line per tenant, then the LLM's cost:

```text
lab: ACT=12 ATTEND=310 TRACK=26865 review=40 errors=0 ignored=0 llm_calls=120 llm_fallbacks=0 -> /data/output/lab
  LLM: 120 questions, 104 from the cache, 3200+900 tokens, 41.0 s, gpt-oss, reasoning off
```

The same figures are in the chat (« Où en sommes-nous ? », `llm_usage`). What to look at:

| Seen | Meaning | Action |
| --- | --- | --- |
| Hours of GPU, few new decisions (« Qu'est-ce qui a changé depuis le run d'hier ? ») | The LLM is asked again what it already answered | `NGVM_LLM_REASONING=off` on the group (`docs/llm.md`); the cache is on by default on Kubernetes (`/data/llm-cache.json`) |
| `from_cache` close to `questions` from the second run | The cache works: only the new or changed CVEs cost | — |
| Thousands of completion tokens per question | The model reasons before answering | `NGVM_LLM_REASONING=off` (`docs/llm.md`) |
| `review` in the thousands | Rows asking an analyst whose doubt changes nothing | `policy.review: decisive` (the default since v0.23.7) |

### The watch and its alerts

```bash
kubectl -n ngvm-lab logs job/$(kubectl -n ngvm-lab get jobs -l app.kubernetes.io/component=watch --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2)
kubectl -n ngvm-lab logs deploy/ngvm-lab-via --tail=20
kubectl -n ngvm-lab logs deploy/ngvm-lab-sender --tail=20
```

Analysts validate the alerts on the review page (`https://<NGVM_ALERTS_HOST>`); the sender mails
them within a minute. An alert never makes a ticket. The last watch passage in one command (expected:
`sources: …`, `intel: N/N records from the shared service` with the shared service, `lab: N new
items, N alerts`, no `ERROR`):

```bash
kubectl -n ngvm-lab get jobs --sort-by=.metadata.creationTimestamp -o name | grep watch | tail -1 | xargs kubectl -n ngvm-lab logs --all-containers --tail=30
```

### The radar and the shared intelligence service (v0.22.0)

The watch team's tenant (`team` here, namespace `ngvm-team`) runs the shared intelligence service
and the radar; the other tenants read their CVE records and the radar's feed from it
(`docs/radar.md`).

```bash
kubectl -n ngvm-team logs deployment/ngvm-team-intel | grep -v httpx | head -5
kubectl -n ngvm-team get jobs --sort-by=.metadata.creationTimestamp -o name | grep watch | tail -1 | xargs kubectl -n ngvm-team logs --all-containers --tail=30
```

The service starts with `intel: tokens radar 1, read 1; …`, then logs the requests it serves. Each
radar passage logs `radar: N events in 14 days, alert at 4 (urgent 7); best: …` (v0.22.1): a
passage without alerts shows how far the best events are from the thresholds. The team's daily run
has nothing to scan: `NGVM_K8S_SUSPEND=true` keeps it suspended (a `kubectl patch` is undone by the
next deployment).

### Remediation tickets (v0.20.0)

The step `dispatch` at the end of each daily run sends the tickets of `tickets.automatic` in
`dispatch.yaml` (`act`: the ACT decisions only); a person sends others from the page of the
requests. In `mode: dry-run` they stay `proposed`; the first daily run in `live` sends them. A change
of `dispatch.yaml` takes effect at the next deployment.

```bash
kubectl -n ngvm-lab get jobs --sort-by=.metadata.creationTimestamp -o name | grep daily | tail -1 | xargs kubectl -n ngvm-lab logs -c dispatch
kubectl -n ngvm-lab logs deployment/ngvm-lab-dispatch --tail=20
```

The step ends with `dispatch of run … (<mode>): proposed n, sent n, updated n, fixed n, …`. The
tickets themselves: `docs/dispatch.md` §4.

### Deploy again

`deploy-k8s` runs on a push to the default branch, a "Run pipeline" from the GitLab page, or a
pipeline made through the API on the default branch (v0.23.18: `glab ci run -b main`, or
`POST /projects/:id/pipeline` with a token that has the Developer role on the project). An old job
may not be retried. To deploy again without a change, from the project's clone:

```bash
glab ci run -b main
```

Without `glab`, an empty commit does the same:

```bash
git commit --allow-empty -m "Redeploy"
git push
```

Before v0.23.18, a tenant on Kubernetes with `NGVM_REPORTING_DSN` could not use "Run pipeline":
GitLab refused it (`'publish' job needs 'triage' job, but 'triage' does not exist in the
pipeline`), and its schedules failed the same way.

## 3. Check the state

| Command | Expected |
| --- | --- |
| `kubectl -n ngvm-lab get pods \| grep -v -E "Running\|Completed"` | The header line only |
| `kubectl -n ngvm-lab get pods` | Services `Running`; the last daily job `Completed`; watch jobs `Completed` every 10 minutes |
| `kubectl -n ngvm-lab get deploy -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[0].image}{"\n"}{end}'` | Every NGVM image at the tag of the tenant's `.gitlab-ci.yml` |
| `kubectl -n ngvm-lab logs deploy/ngvm-lab-verdict \| head -1` | `store postgresql … (TLS verified)` with the tenant's database, else `store files …`; then `latest run …` |
| `kubectl -n ngvm-lab logs deploy/ngvm-lab-via \| grep store` | The same for the watch service, with the number of alerts kept |
| `kubectl -n ngvm-lab get pods -l cnpg.io/cluster=ngvm-lab-db` | The database instance(s) `Running` |
| `kubectl -n ngvm-lab logs deploy/ngvm-lab-verdict --tail=5` | A `push tenant=lab run=… rows=…` line after each daily run |
| `kubectl -n ngvm-lab logs deploy/ngvm-lab-dispatch \| head -1` | With `dispatch.yaml` (v0.20.0): its store, mode (dry-run or live), targets, automatic levels and targets of the requests; each daily run's container `dispatch` ends with `dispatch of run … : proposed n, sent n, …` (`docs/dispatch.md`) |
| `helm -n ngvm-lab get values ngvm -o yaml` | What `deploy-k8s` set (database, chat, watch, sign-in, dispatch, intel) |
| `kubectl -n ngvm-team logs deployment/ngvm-team-intel \| grep -v httpx \| head -1` | `intel: tokens radar 1, read N; …` (the watch team's tenant, v0.22.0) |

In the chat: "summary of the latest run" names the run and its date; "details of asset web01"
shows an asset, with its scans since v0.18.1, even when it has no finding.

## 4. Known failures and remedies

| Symptom | Cause | Remedy |
| --- | --- | --- |
| Daily run `Init:Error`, step `collect`: "no detection received from the collectors", each source "nothing received yet" | The detection service has nothing yet: a new database, collectors not run since, or their pushes refused | Run the connectors on the collector (§2), check the pushes in the detection service's log, then the daily run again |
| Step `collect`: "Another run holds the working volume" | A daily run is still running, or one was killed holding the lock | Wait for it; a lock older than the run's deadline (`daily.activeDeadlineSeconds`) is taken over by the next run |
| Step `collect`: a source "older than max_age_hours" | The collector did not push today (timer, scan failed) | Its journal on the collector; the run goes on with the other sources |
| Collector: `docker pull` or `podman pull` "HTTP Basic: Access denied" | The registry login of the VM has expired or its deploy token was revoked; or `docker login` used another user name than the token's | A new deploy token and a new login (§5, "Registry login of a collector") |
| Collector journal: `FAIL <host> [trivy]` or `[dnf-updateinfo]` (v0.18.2) | That host could not be scanned over SSH: off, key refused, scanner missing; the reason follows | `docs/scanning.md` §3 (test by hand from the collector); the other targets are pushed |
| Collector journal or job log: OpenVAS "timed out" | gvmd did not answer one command within `gmp_timeout_seconds` (300 s): feed loading, large report. Since v0.18.2 a new connection is made (`new connection 1/3`); "after 3 reconnections" means gvmd stayed silent | Raise `gmp_timeout_seconds` in the `openvas` section of `targets.yaml` (`docs/openvas.md` §4); the scan goes on in gvmd and the next run waits for it or collects it |
| Collector journal: `FAIL cmdb [...]` (v0.19.0) | iTop not reached, its certificate not trusted (`ca_file`), the account refused (`code 1`) or without read rights on the CIs | `docs/cmdb.md` §5; the daily run keeps the previous CMDB detection while it is younger than `max_age_hours` |
| A host "not in the CMDB", or a server "never scanned" (v0.19.0) | The CMDB and the scans disagree: an item missing, a name or an address different, a target missing | The `coverage` dashboard and `list_coverage` in the chat; `docs/cmdb.md` §6 |
| Collector journal: push refused `401` or `403` | Token of the collector changed or not declared in `collectors.yaml` | `docs/collectors.md` (declaration and tokens) |
| Watch: `inventory none yet` | The daily run has not pushed its inventory to the watch service (step `inventory`; needs `NGVM_RUN_MODE: kubernetes`) | The log of the step `inventory` of the last daily run; it warns, and says what the watch keeps (since v0.23.19), when the service cannot be reached or refuses it |
| Services restart two or three times after `NGVM_DATABASE=true` | They wait for the database's secret while the cluster initialises | None: they settle within two minutes |
| A service in `CrashLoopBackOff`, its log: "the tables of … are not isolated by tenant … refusing to start" (v0.27.3) | A table of its schema is not kept to one tenant: usually a database restored from a dump made before v0.25.0 (policies testing the setting of the older name); up to v0.27.2 the services saw an empty tenant without a word | Repair once, as the database's superuser, then restart: `docs/kubernetes.md` §5.1 |
| The chat: "This model's maximum context length is 16384 tokens …" | The tools' definitions (about 10,000 tokens for all of them) and their answers fill a small context | `NGVM_CHAT_TOOLS=core` and `NGVM_CHAT_MAX_CHARS=4000` on the project (v0.27.4), or a larger `--max-model-len` for the model: `docs/chat.md` §9a |
| The chat says a CVE does not concern the tenant, published after the daily run | Before v0.27.4, `get_cve` read « not in the run » as « not concerned » | v0.27.4: the answer says `newer_than_run`; meanwhile `list_alerts` and `list_new_cves` |
| Watch log: "POST /watch/runs refused (413)", the same alerts drafted again at each passage | Before v0.27.4, a passage that drafted many alerts did not fit in one body and was never recorded | v0.27.4 sends its files in batches; before, raise `NGVM_WATCH_MAX_MB` |
| `deploy-k8s`: "ERROR NGVM_INTEL_URL points at the service … which does not exist" (v0.27.3) | The variable names a Service of the cluster that is not there (a typo, a namespace or a release renamed); the same for the relay, the LLM and the reporting addresses | Correct the variable (`kubectl -n <ns> get services` lists those there), then deploy again; nothing was changed |
| A job: "WARN  NGVM not fetched from …" then "ERROR NGVM v… could not be fetched … by any address" (v0.27.5) | No address answered: the job token not allowed on the code project, `NGVM_REF` not a tag of it, or GitLab not reached from the runner; each `WARN` gives git's reason, without the token | The allowlist of the code project (`docs/deployment.md` §4), the tag, the runner's network; before v0.27.5 a group `NGVM_SERVER_URL` sent the runners of the LAN to the public address (403): remove it. In v0.27.5 only, a runner outside the LAN tried GitLab's internal address twice (`Could not resolve host`): put `NGVM_SERVER_URL` back in its environment, or move to v0.27.6 |
| A triage step of nearly an hour, `LLM: … 182.5 s` but `deciding 3402 s` (before v0.28.0) | Rationales the LLM did not answer in time: each asked three times, 180 s each, with the other questions of its batch waiting; that time was counted nowhere | v0.28.0 asks once, counts the time (`LLM: n question(s) without an answer … s spent waiting`), leaves the LLM aside after three questions not answered in time (`llm.tasks.max_timeouts`) and no longer waits by batches; then why the server is slow: its load (the chat, the watch), its context, `NGVM_LLM_*` |
| Step `via`: "ERROR the relay of the sources … cannot be reached" (v0.27.7) | The relay does not answer: stopped (out of its hours, a cloud incident), its address changed, a firewall; before v0.27.7 a trace ending with `deltaLog.json: timed out` | Start the relay, or run the daily run and the watch within its hours (`NGVM_K8S_SCHEDULE`, `NGVM_WATCH_SCHEDULE`, `deploy/relay/README.md`); then the daily run again |
| Step `via`: "WARN CVEs published since … not read" or "KEV additions … not read" (v0.27.7) | That list could not be read; the CVEs found by the scanners are triaged all the same | None if it does not last; the newly published CVEs come with the next run |
| `deploy-k8s`: "the CloudNativePG operator is not installed" | `NGVM_DATABASE=true` without the operator: the cluster's API answered, without `postgresql.cnpg.io` (before v0.23.19, also a failed discovery) | `deploy/cnpg/README.md` |
| `deploy-k8s`: "the cluster's API did not answer the discovery through the agent … 3 times" (v0.23.19) | The GitLab agent's tunnel failed three times in a row; the `WARN` lines above give `kubectl`'s error | Run the pipeline again; if it lasts, the agent's pod (`kubectl -n gitlab-agent get pods`) and its log |
| `helm get values` shows no `database` although `NGVM_DATABASE` is set | The job did not see the variable: protected variable on an unprotected branch, wrong name or value | Settings > CI/CD > Variables: `NGVM_DATABASE` = `true`, then run the pipeline again |
| Step `publish`: "schema version 2 … run `verdict db init`" | The reporting database is older than the release | `verdict db init` once (`docs/reporting.md`) |
| The chat says "no run received yet" | The decision service has no run (new database) | A daily run (§2) |
| The chat does not find an asset | Before v0.18.1, an asset with no finding was not listed; since, an asset not scanned in the run | Since v0.18.1, check its scans in the remediation dashboard ("Assets by last scan") and the collector |
| A finding "gone without a new scan" (v0.18.1) | Its asset was not scanned again by the source that had seen it | The asset's scans (collector journal, targets); it is counted fixed only after a new scan |
| A French Grafana bar chart shows no bar (v0.17.3) | Dashboard imported before v0.18.1 | Import the French dashboards again |
| `deploy-k8s`: `UPGRADE FAILED: cannot patch "ngvm-<tenant>-watch" … $setElementOrder` | The watch CronJob of v0.21.0 or v0.22.0 gave `NGVM_CACHE_DIR` twice, which breaks the patch once the environment changes (fixed in v0.22.1) | `kubectl -n ngvm-lab delete cronjob ngvm-lab-watch`, then deploy again (§2); before moving to v0.22.1, delete it the same way |
| A job `Pending`: "no runners … scan-cloud" | The cloud scanner is stopped or its runner is offline | Start the scanner, or `sudo systemctl restart gitlab-runner` on it; the job starts by itself |
| `glab ci retry`: "Job is not retryable" | A newer pipeline exists | Deploy again (§2) |
| Sender: "LibreOffice is not installed in the job" | `alerts.attach: [pdf]`, and the sender's image has no LibreOffice | `attach: [docx]`, then validate the alert again |
| No ticket in the ITSM | `mode: dry-run`, no decision of the automatic levels, or no daily run since `live` | The line `dispatch of run …` of the last daily run (§2) |
| Watch or daily log: "records read from the sources directly" | The shared intelligence service did not answer | Its log (§2), `NGVM_INTEL_URL` and `NGVM_INTEL_TOKEN` of the group |
| Review page: Keycloak "Invalid redirect URI" | The page's address is not declared in the client | Add `https://<NGVM_ALERTS_HOST>/oauth2/callback` to the client's redirect URIs |
| The watch team's daily run is no longer suspended | A deployment undid a `kubectl patch` | `NGVM_K8S_SUSPEND=true` (v0.22.1) |

## 5. Upgrades

### NGVM itself (the code project)

1. Push the release branch and open its merge request in one step:

   ```bash
   git push -o merge_request.create -o merge_request.target=main -o merge_request.title="Release X.Y.Z" origin release-X.Y.Z
   ```

2. When the merge request's pipeline is green, merge it in GitLab, then check what is on the
   server before tagging:

   ```bash
   git checkout main && git pull --ff-only origin main
   git show origin/main:deploy/charts/ngvm-tenant/Chart.yaml | grep -c X.Y.Z
   git tag vX.Y.Z origin/main && git push origin vX.Y.Z
   ```

   The count must be `2` (`version` and `appVersion`). The tag's pipeline builds the images.

### A tenant

When the tag's `images` job is green: in the tenant project, change `ref` and `NGVM_REF` in
`.gitlab-ci.yml` and push; `deploy-k8s` redeploys. Read the release's **Upgrade** paragraph in
`CHANGELOG.md` first: some releases need `verdict db init` on the reporting database, or a
dashboard imported again.

### Registry login of a collector

A collector pulls its image from the registry of the code project with a deploy token of its own,
read-only, that can be revoked without touching the cluster:

1. In GitLab, project `vulnops/ngvm` > Settings > Repository > Deploy tokens > Add token:
   name and **Username** `collector-<host>` (left empty, GitLab makes `gitlab+deploy-token-<n>`,
   shown in the list of tokens), an expiry date, scope **`read_registry` only** (no
   `read_repository`, no `write_registry`). GitLab shows the password once.
2. On the collector, log in with the token's **user name**, the password pasted at the prompt
   (not echoed, not kept in the shell history):

   ```bash
   read -rsp 'Deploy token password: ' T && echo && printf '%s' "$T" | sudo docker login registry.example.org:5050 -u collector-scan01 --password-stdin; unset T
   ```

   `Login Succeeded` is expected; Podman: `sudo podman login` with the same options. Still
   "Access denied": the user name is not the token's, the scope is not `read_registry`, or the
   token has expired (the list of deploy tokens shows all three).
3. Note the expiry date: the next pull after it fails the same way.

### A collector

```bash
sudo docker pull <registry>/vulnops/ngvm/detect:vX.Y.Z
sudo sed -i 's#/detect:v[0-9.]*#/detect:vX.Y.Z#' /etc/systemd/system/ngvm-collector@.service
sudo systemctl daemon-reload
```

The push contract (`detect.v1`) only grows: a collector of an older release still pushes, but
misses the fixes of the collection made since.

## 6. Stopping and starting the cluster

When the Kubernetes cluster is stopped for the night and started in the morning:

- The services, the database and the chat start again by themselves; the services may restart
  once while the database comes up.
- A schedule missed while the cluster was down: the daily run (no deadline) starts once when the
  cluster is back; the watch (`startingDeadlineSeconds` 300) skips what is older than 5 minutes and
  resumes at its next slot. Check with `kubectl -n ngvm-lab get jobs`; start the daily run by hand
  (§2) if none ran.
- The collectors and the external scan do not depend on the cluster: their pushes made while it
  was down are kept in the collector's spool and sent at the next run of the connector.
