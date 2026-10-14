# AVA 01610-1 — DEVITO Read-only Repository Audit

- **Prüfdatum:** 2026-10-14
- **Repository:** `hv2znbvdy9-glitch/DEVITO`
- **Referenz:** `main`
- **Referenz-Commit:** `6c86dc83122952c45375adb20a7c69162044a879`
- **Prüfmodus:** GitHub-Lesezugriff, Inventar und statische Text-/Risikomusterprüfung
- **Änderungen an Anwendungscode:** keine
- **Skriptausführung / lokale Systemänderungen:** keine
- **Workflow-Dispatch / Retry:** keiner durch diesen Audit

## 1. Ergebnis und Abgrenzung

Der aktuelle GitHub-Dateibaum wurde rekursiv gelesen. Alle 42 Python- und 30 PowerShell-Dateien wurden abgerufen und einem statischen Suchlauf auf sicherheitsrelevante Muster unterzogen. Zusätzlich wurden ausgewählte kritische Dateien und Workflows vertieft gelesen.

Dies ist ein **Inventar- und statischer Zwischen-Audit**, noch keine Bestätigung eines vollständigen manuellen Zeile-für-Zeile-Codeaudits und kein Laufzeitnachweis. Die Tests wurden durch diesen Audit nicht gestartet. Ein erfolgreiches GitHub-Workflow-Ergebnis belegt nur die in diesem Workflow tatsächlich ausgeführten Schritte.

## 2. Aktueller Bestand

| Bereich | Aktueller Befund |
|---|---:|
| Git-Tree-Einträge einschließlich Verzeichnissen | 139 |
| Dateien/Blobs | 114 |
| Python-Dateien | 42 |
| PowerShell-Dateien | 30 |
| Workflow-YAML-Dateien | 8 |
| AVA-benannte Pfade | 73 |
| Tests unter `tests/` | 12 Python-Dateien einschließlich Unterverzeichnissen |

Die Werte ersetzen die ältere Inventarangabe „109 Dateien / 39 Python-Dateien“ für den geprüften `main`-Stand. Die Kategorien überlappen und sind nicht additiv.

Die angegebene AVA-Paketstruktur ist im Repository vorhanden, unter anderem `ava/cli`, `ava/clients`, `ava/config`, `ava/core`, `ava/db`, `ava/lsp`, `ava/monitoring`, `ava/utils`, `ava/neuron_models.py`, `ava/policy.py` und `ava/policy_cli.py`.

Die aufgelisteten PowerShell-Programme befinden sich überwiegend unter `scripts/`, nicht im Repository-Stamm. Der Sensor liegt unter `scripts/AVA_WLAN_TANGLE_SENSOR.ps1`. Verweise auf die entsprechenden Stamm-Pfade müssen korrigiert oder ausdrücklich als lokale, nicht eingecheckte Dateien gekennzeichnet werden.

## 3. Wesentliche technische Befunde

### 3.1 Python-Ausführungsengine — hohe Priorität

Datei: `ava/core/engine.py`

Die Engine startet Befehle mit `subprocess.run(..., shell=True)` und asynchron mit `asyncio.create_subprocess_shell(...)`. Eine einfache Befehlsvalidierung ersetzt keine belastbare Vertrauensgrenze. Wenn ein Aufgabenbefehl aus nicht vertrauenswürdigen Daten stammen kann, entsteht ein Risiko durch Shell-Injection und unbeabsichtigte Prozessausführung.

**Empfehlungen**
1. Herkunft und Berechtigungsmodell für `Task.command` dokumentieren.
2. Wenn möglich feste Programme mit Argumentlisten verwenden (`shell=False`), statt beliebige Shell-Strings anzunehmen.
3. Zulässige Befehle über eine explizite Allowlist und strukturierte Parameter definieren.
4. Tests für Shell-Metazeichen, ungültige Befehle, Timeouts und Fehlerpfade ergänzen.
5. Hintergrundtask-Zustände und Fehlerausgänge getrennt testen.

### 3.2 WLAN-Tangle-Sensor — nicht strikt read-only

Datei: `scripts/AVA_WLAN_TANGLE_SENSOR.ps1`

Der Sensor liest sichtbare WLAN-Informationen über `netsh wlan show networks mode=bssid`, lokale Adapter/IP-Konfiguration und IPv4-Nachbarn. Gleichzeitig schreibt er Dateien in `C:\Windows\SecurityGuardian`: Ereignis-JSONL, Tangle-JSONL, Tangle-State, HTML-Portal und Policy-JSON.

Wichtig: `Ensure-Dirs` wird bereits vor der Auswertung von `-RemoveTask` und `-InstallTask` aufgerufen. Der Aufruf kann also Verzeichnisse erstellen und `ava_admin_policy.json` überschreiben, auch wenn anschließend nur ein Task entfernt werden soll. `-InstallTask` registriert eine geplante Aufgabe als `SYSTEM`; `-RemoveTask` entfernt sie. `-Loop` läuft dauerhaft.

**Empfehlungen**
1. Modusgrenzen explizit machen: `-RunOnce` = lokale Erfassung mit gekennzeichneten Artefakt-Schreibvorgängen; `-InstallTask` / `-RemoveTask` = privilegierte Systemänderungen.
2. Verzeichnisse und Policy-Datei erst in dem Modus vorbereiten, der diese Schreibvorgänge benötigt.
3. Policy-Datei nicht bei jedem Start blind überschreiben; vorhandene Datei validieren und Änderungen gesondert protokollieren.
4. Exit-Code von `netsh` prüfen und Fehler von „keine Netzwerke gefunden“ unterscheiden.
5. Hash-Kette gegen Manipulation testen: ungültiger State, fehlender vorheriger Hash, beschädigte JSONL-Zeile, konkurrierende Schreibvorgänge und Zeitzonen-/Zeitformat.
6. SSIDs, BSSIDs, IP-Adressen und Nutzernamen als potenziell sensible lokale Telemetrie klassifizieren.

### 3.3 PowerShell-Skripte: Fähigkeiten vor Ausführung klassifizieren

Der Musterlauf findet in mehreren Skripten administrative Anforderungen, Datei-/State-Schreibvorgänge und Firewall-/Task-Funktionen. Beispiele sind `AVA-SecurityGuardian.ps1`, `AVA_Immune_System_v2.ps1`, `AVA_v4_Portal.ps1`, `AVA_SOC_CORE.ps1`, `AVA_CORE_STACK_v1.ps1` und Portal-/Scan-Varianten.

Die bloße Anwesenheit eines Befehls ist noch kein Beweis, dass er in jedem Lauf ausgeführt wird. Sie reicht jedoch aus, um ein Skript nicht ohne weitere Analyse pauschal als „read-only“ einzustufen. Insbesondere `AutoBlock`, Firewall-Regeländerungen, Task-Registrierung, Task-Entfernung und Rollback müssen als getrennte, ausdrücklich autorisierte Funktionen behandelt werden.

Die Dateien `scripts/AVA_SOC_V7_SAFE_READONLY.ps1` und `scripts/AVA_SOC_CORE_CLEANED.ps1` sind kleinere Kandidaten für eng begrenzte statische Prüfungen. Auch die Bezeichnung „READONLY“ ist allein kein Sicherheitsnachweis.

### 3.4 Statisches Audit-Werkzeug — nützlich, aber nicht vollständig

Datei: `tools/Invoke-AvaSafeAuditStatic.ps1`

Das Werkzeug erzeugt Datei-Inventare mit SHA-256, Parsergebnisse für PowerShell-Dateien und einen Vergleich einer bereinigten Skriptvariante mit Listen verbotener Befehle/Textmuster. Es schreibt erwartungsgemäß Audit-Artefakte in ein angegebenes Ausgabeverzeichnis.

**Grenzen:** Musterlisten können Aliase, dynamisch konstruierte Befehle, indirekte Aufrufe und kontextabhängige Laufzeitwirkungen übersehen. Ein erfolgreicher statischer Bericht ist kein Ersatz für Review, isolierte Tests oder einen nachgewiesenen Windows-Testlauf.

## 4. Tests und GitHub Actions

Vorhandene Testdateien umfassen unter anderem:

- `tests/test_engine.py`
- `tests/test_cli_start.py`
- `tests/test_config.py`
- `tests/test_isc_client.py`
- `tests/test_lsp.py`
- `tests/test_real_state.py`
- `tests/test_utils.py`
- `tests/test_ava_policy_acceptance.py`
- `tests/test_action_policy_acceptance.py`
- `tests/test_ava_ave_avo_viv_01610_15.py`
- `tests/test_run_workflow_command.py`
- `tests/performance/test_performance.py`

Es sind acht Workflow-YAML-Dateien vorhanden: `ava-3-14-defensive-run.yml`, `ava-ave-avo-viv-01610-15.yml`, `ava-policy.yml`, `ava-safe-audit-one-script.yml`, `psscriptanalyzer.yml`, `run-all-safe.yml`, `safe-audit-verified-pr.yml` und `safe-audit.yml`.

Die aktuellen Workflow-Definitionen und historischen Runs dürfen nicht miteinander verwechselt werden. Ein `workflow_dispatch`-Trigger allein startet keinen Lauf. Für eine vollständige CI-Matrix müssen je Workflow Trigger, Pfadfilter, Berechtigungen, Runner, tatsächlich ausgeführte Schritte, Artefakte und der Run-Status zum geprüften Commit dokumentiert werden.

### Live abgefragte Workflow-Belege

- `AVA AVE AVO VIV 01610-15 — Lindblad Qubit Check`: **completed / success**, Run [38458673749](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38458673749), Commit `6c86dc83122952c45375adb20a7c69162044a879`.
- `Run AVA Safe Audit`: **completed / success**, Run [37975543865](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/37975543865), Commit `cc92be61342fd800ff4601dfec0f5a916c268049`.
- `PSScriptAnalyzer`: letzter in der abgefragten Ergebnisliste sichtbarer Lauf **completed / success**, Run [37044562043](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/37044562043), Commit `eb344036daeb736974f065eab845baf2c406a52c`.
- Ein älterer Lauf mit dem Namen `AVA Safe Audit` ist fehlgeschlagen: [Run 37044796548](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/37044796548). Der genaue Fehler ist in diesem Inventarbericht nicht diagnostiziert.
- Zum Zeitpunkt der Abfrage lief außerdem ein Copilot-Agent-Run [38571616620](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38571616620). Das ist kein AVA-Produkttest.

**Wichtig:** Keiner dieser Läufe wurde für diesen Audit erneut gestartet. Die Links zeigen vorhandene GitHub-Belege; sie belegen nicht automatisch den aktuellen Status aller acht Workflows.

## 5. Priorisierter Arbeitsplan

1. **P0 — Ausführungsgrenze:** Shell-Ausführung in `ava/core/engine.py` absichern und durch Negativtests abdecken.
2. **P0 — Systemänderungen:** Alle PowerShell-Skripte nach Fähigkeiten klassifizieren: reine Beobachtung, lokale Artefakt-Schreibvorgänge, Task-/Service-/Firewall-Änderungen, Prozessstarts.
3. **P1 — WLAN-Sensor:** Policy-Überschreiben beim Start vermeiden; Task-Verwaltung vom Sensorzyklus trennen; Parser- und Hashketten-Tests ergänzen.
4. **P1 — Tests:** Bestehende Tests und Abhängigkeiten auflisten und in einer kontrollierten CI-Ausführung nachweisen. Erst nach expliziter Freigabe einen neuen Lauf starten.
5. **P1 — Workflows:** Trigger-/Pfadfilter und Berechtigungen gegen den echten Dateibaum prüfen; veraltete Pfade und uneindeutige „read-only“-Beschreibungen korrigieren.
6. **P2 — Dokumentation:** Für jede Komponente Datei-SHA, Schnittstellen, Eingaben/Ausgaben, Schreibwirkungen, Risiken, Tests und letzten belegten Run vermerken.
7. **P2 — Evidenzintegrität:** Audit-Berichte append-only versionieren; ursprüngliche Artefakte nicht überschreiben; Zeitstempel, Commit-SHA und Prüfsummen miteinander verknüpfen.

## 6. Evidenzgrenze und nächster Status

- Repository-Inventar und Text-/Risikomusterprüfung: **durchgeführt**.
- Vertiefte Prüfung ausgewählter kritischer Dateien: **durchgeführt**.
- Vollständiger manueller Zeile-für-Zeile-Review aller Dateien: **offen**.
- Tests durch diesen Audit: **nicht ausgeführt**.
- Windows-Laufzeitprüfung des WLAN-Sensors: **nicht ausgeführt**.
- Neue GitHub-Workflows/Retry: **nicht gestartet**.
- Änderungen an Anwendungscode oder Systemkonfiguration: **keine**.

Leitlinie: **BEOBACHTEN → EVIDENZ → PLANEN → TESTEN → NACHWEIS**. Keine erfundenen Runs; kein Laufzeitstatus aus bloßem Quelltext ableiten.


## 7. Ergänzung nach Auswertung konkreter Workflow-Logs (2026-10-14)

Diese Ergänzung basiert auf den vorhandenen Job-Logs und auf den dazugehörigen Quelltexten. Es wurden keine Workflow-Läufe erneut gestartet.

### 7.1 AVA Safe Audit: Parserfehler im aktuellen main bestätigt

- **Run:** [37044796548](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/37044796548), Attempt 28
- **Geprüfter Commit:** `cc92be61342fd800ff4601dfec0f5a916c268049`
- **Fehlgeschlagener Job:** `Inventory, parse, sanitize, isolated test`
- **Abbruchschritt:** `Parse every PowerShell file statically`
- **Betroffene Datei:** `scripts/AVA_SOC_PORTAL_V6_SAFE.ps1`
- **Datei-Blob-SHA im aktuell gelesenen main:** `87a782efcd0e5c7d26abe22d7e9c325755888eb8`

Die Logs melden:
- Zeile 291: fehlende schließende `}` in Statement-Block oder Typdefinition.
- Zeile 298: unerwartetes Token `firewall`.
- Zeile 307: unerwartetes Token `}`.

Der untersuchte Quelltext enthält innerhalb eines geordneten Hashtable-Literals direkte Statement-Ausdrücke wie `defender = try { ... } catch { ... }` und `firewall = try { ... } catch { ... }`. Diese Konstruktion ist die belegte Fehlerstelle, die der Parser beanstandet. Weil der Blob-SHA im aktuellen `main` mit dem aus der fehlgeschlagenen Revision gelesenen Blob übereinstimmt, ist dieser Befund **nicht bloß historisch: er besteht im derzeit geprüften main-Dateistand weiter**.

**Korrekturvorschlag, nicht ausgeführt:** Collector-Ergebnisse zunächst in Variablen mit separaten `try/catch`-Blöcken erfassen und diese Variablen danach dem Hashtable zuweisen. Anschließend zunächst nur den PowerShell-AST-Parser über diese einzelne Datei laufen lassen; erst danach die vollständige statische Audit-Workflow-Prüfung erneut autorisieren.

### 7.2 PSScriptAnalyzer: frühere Warnungs-Fail-Policy inzwischen geändert

- **Historischer fehlgeschlagener Run:** [35533968161](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/35533968161), Attempt 21
- **Geprüfter Commit:** `62f25d7df4e3696f8c13bede2abee5c348dc0160`

Der historische Workflow warf einen Fehler, sobald `$results` irgendeinen Befund enthielt. Dazu zählten auch Warnungen, etwa:
- `PSAvoidUsingCmdletAliases` für den Alias `H`
- `PSUseApprovedVerbs` bei Funktionsnamen
- `PSUseDeclaredVarsMoreThanAssignments` bei ungenutzten Variablen
- `PSUseShouldProcessForStateChangingFunctions` bei Funktionen, deren Namen auf Zustandsänderungen hinweisen.

Das ist als **Lint-/Best-Practices-Fehler** dokumentiert, nicht als Syntaxfehler.

Der auf `main` gelesene Workflow wurde in dieser Hinsicht angepasst: Er markiert Warnungen und Fehler getrennt und beendet den Job nur dann mit Fehler, wenn mindestens ein Befund der Severity `Error` vorliegt. Warnungen allein werden ausdrücklich zugelassen. Ein bestehender erfolgreicher Lauf ist [37044562043](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/37044562043). Damit ist die frühere „jede Warnung ist fatal“-Policy im aktuellen Workflow-Quelltext korrigiert; das bedeutet nicht, dass sämtliche Warnungen beseitigt wurden.

### 7.3 AVA Neuro Tangle Safe Check: wahrscheinlich veralteter nativer Exit-Code

- **Run:** [34977308611](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/34977308611), Attempt 26
- **Commit:** `840359c35bc3b7bc05ca8f1df3b02703fe04ad6f`
- **Beobachtung aus Logs:** AST-/Negativtests erfolgreich; der Zwei-Zyklen-Nachweis gibt `AVA 01610 1 two-cycle evidence verification passed` aus, der Schritt endet dennoch mit Exit-Code 1.

Der damals geprüfte Sensor rief `netsh.exe wlan show networks mode=bssid` auf und prüfte anschließend `$LASTEXITCODE`. Bei einem Fehler wurde eine Exception ausgelöst; der umgebende `Invoke-AVASafeCollect`-Block fing diese ab und konnte den Collector als nicht verfügbar protokollieren. Der Workflow verwendete den eingebauten `shell: powershell`-Modus. GitHub Actions hängt an diesen eingebauten PowerShell-Shells einen Wrapper an, der einen vorhandenen `$LASTEXITCODE` als Prozess-Exit-Code verwendet.

**Wahrscheinliche, aber nicht abschließend bewiesene Ursache:** Ein nicht erfolgreicher nativer WLAN-Collector hinterließ `$LASTEXITCODE = 1`; obwohl der Sammlungsfehler intern behandelt und die Evidenzprüfung erfolgreich ausgegeben wurde, lieferte der Shell-Wrapper anschließend Exit-Code 1. Der Log enthält nicht den konkreten nativen Exit-Code im abschließenden Fehlertext, daher wird dies als Hypothese und nicht als bewiesene Ursache geführt.

Referenzen:
- [PowerShell automatische Variablen – `$LASTEXITCODE`](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/about/about_automatic_variables)
- [GitHub Actions – Exit-Codes bei eingebauten PowerShell-Shells](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#exit-codes-and-error-action-preference)

**Korrekturvorschlag, nicht ausgeführt:** Den nativen Exit-Code unmittelbar nach dem Aufruf lokal speichern, ihn im Collector-Ergebnis explizit ausgeben und nach bewusst abgefangenem Collector-Ausfall den Schritt-Exitstatus kontrolliert normalisieren. Gleichzeitig sicherstellen, dass unbehandelte Fehler weiterhin zuverlässig zum Fehlerstatus führen.

### 7.4 AVA · AVE · AVO · VIV 01610-15: aktueller Forschungsnachweis

- **Workflow:** [AVA AVE AVO VIV 01610-15 — Lindblad Qubit Check](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38458673749)
- **Commit:** `6c86dc83122952c45375adb20a7c69162044a879`
- **Status:** `completed / success`
- **Matrix:** Python 3.10 und Python 3.12; beide Jobs erfolgreich.
- **Tests je Matrix-Job:** 6 fokussierte `unittest`-Tests bestanden; anschließend numerischer Smoke-Test erfolgreich.

Die Tests decken ab: stationären angeregten Zustand bei Null-Dissipation und σz-Hamiltonian, analytischen Populationsverlauf für Amplitudendämpfung, Kohärenzabnahme bei reiner Dephasierung, Spur/Hermitizität/Positivität während einer gemischten Entwicklung, Bloch-Vektor des Plus-Zustands und Zurückweisung ungültiger Parameter.

Der Standardlauf verwendet laut Quellcode die feste RK4-Zeitschrittintegration mit Dauer (2.0), Δt (= 0.005), 400 Schritten, ω (=1.0), γ-relaxation (=0.7) und γ-dephasing (=0.2). Der Workflow-Log zeigt in beiden Python-Versionen:
- `trace_real = 1.0`
- `trace_imag = 0.0`
- `hermiticity_error = 0.0`
- `is_density_matrix_within_1e-8 = true`
- `purity = 0.628426197367`

**Interpretation:** Dies ist ein erfolgreicher, reproduzierbar definierter numerischer Check des implementierten Ein-Qubit-Lindblad-Modells in den beiden CI-Python-Versionen. Die Ergebnisse belegen nicht für sich allein eine neue physikalische Entdeckung, tatsächlichen Messkollaps oder physische Quantenausführung. Der Integrator ist laut Projektcode eine Approximation mit festem Zeitschritt; weitere Konvergenztests über mehrere Δt-Werte und unabhängige Referenzlösungen wären sinnvolle nächste Verifikationsschritte.

Quelltextnachweise:
- [Experiment](https://github.com/hv2znbvdy9-glitch/DEVITO/blob/main/experiments/ava_ave_avo_viv_01610_15.py)
- [Regressionstests](https://github.com/hv2znbvdy9-glitch/DEVITO/blob/main/tests/test_ava_ave_avo_viv_01610_15.py)
- [Workflow-Definition](https://github.com/hv2znbvdy9-glitch/DEVITO/blob/main/.github/workflows/ava-ave-avo-viv-01610-15.yml)

## 8. Aktualisierter Status nach Log-Prüfung

- Statische Inventur des aktuellen Dateibaums: **durchgeführt**.
- Ausgewählte kritische Python-/PowerShell-Dateien und Workflow-Definitionen: **gelesen und analysiert**.
- Konkrete Fehlerursache des Safe-Audit-Laufs: **Parserfehler belegt; Datei im aktuellen main weiterhin betroffen**.
- Ursache des früheren PSScriptAnalyzer-Laufs: **Warnungen wurden fatal behandelt; aktuelle Workflow-Definition failt nur bei Error-Schweregrad**.
- Neuro-Tangle-Lauf: **Testassertionen protokollieren Erfolg, Job endet mit Exit-Code 1; native `$LASTEXITCODE`-Hypothese noch nicht durch eine direkte Meldung bewiesen**.
- AVA 01610-15 Lindblad-Workflow: **beide Matrix-Jobs und je sechs fokussierte Tests erfolgreich; Diagnosewerte dokumentiert**.
- Skriptausführung, Retry, neuer Produkttest oder Systemänderung durch diesen Arbeitsschritt: **keine**.
- Code-Korrekturen im Repository: **keine**.
- Diese Ergänzung ändert ausschließlich den Audit-Bericht auf dem Audit-Branch.


## 9. Parser-Fix und statischer CI-Nachweis (2026-10-14)

Der zuvor bestätigte Parserfehler in `scripts/AVA_SOC_PORTAL_V6_SAFE.ps1` wurde auf einem separaten Fix-Branch korrigiert; `main` blieb unverändert.

- **Fix-Branch:** `fix/ava-01610-15-soc-portal-v6-parser`
- **Fix-Commit:** [`d8df6b4d753bcc628ce7e280a63a9c1fd1870708`](https://github.com/hv2znbvdy9-glitch/DEVITO/commit/d8df6b4d753bcc628ce7e280a63a9c1fd1870708)
- **Pull Request:** [#180 — fix: repair AVA SOC Portal V6 PowerShell parser](https://github.com/hv2znbvdy9-glitch/DEVITO/pull/180) — offen, nicht gemergt.
- **Parse-only workflow:** [Run 38577253033](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38577253033) — completed / success. Log: `[AVA][PASS] AVA_SOC_PORTAL_V6_SAFE.ps1 parsed successfully.` Der Log bestätigt ausdrücklich, dass das Zielskript nicht ausgeführt wurde.
- **PSScriptAnalyzer:** [Run 38577130310](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38577130310) — completed / success. Es blieben Warnungen bestehen; die aktuelle Workflow-Policy lässt Warnungen zu und bricht nur bei Findings mit Schweregrad `Error` ab.
- **Zusätzlicher Workflow:** `.github/workflows/static-parse-soc-portal-v6.yml`, auf dem Fix-Branch; PowerShell-AST-Parser prüft die Syntax der Zieldatei, ohne deren Inhalt auszuführen.

### Ergebnisgrenze

- Der gezielte Parserfehler ist auf dem Fix-Branch durch den erfolgreichen statischen Parserlauf behoben.
- PSScriptAnalyzer hat keine Error-severity-Findings gemeldet; Warnungen bestehen fort und sind nicht automatisch behoben.
- Keine lokale Windows-Ausführung, keine Firewall-Regeländerung, keine Task-/Service-Änderung, kein Autodefense-/Rollback-Lauf.
- Keine Änderung oder Zusammenführung in `main`; PR #180 bleibt offen.
- Andere Repository-Workflows wurden nicht pauschal gestartet. Die vorhandenen Werkzeuge ermöglichen hier das Auslesen und das durch Push ausgelöste CI, aber keinen direkten `workflow_dispatch`; Ausführung potenziell zustandsändernder Workflows wird nicht durch „blind ausführen“ ersetzt.

Leitlinie bleibt: **BEOBACHTEN → EVIDENZ → PLANEN → TESTEN → NACHWEIS**.


## Nachtrag 2026-10-14 — Merge- und Repository-Run-Status

Dieser Nachtrag korrigiert den obenstehenden Zwischenstand nach erneuter Live-Abfrage. Ältere Aussagen „PR offen/nicht gemergt“ sind durch die folgenden neueren Daten ersetzt.

### Parserkorrektur

- **PR #180 ist gemergt**: https://github.com/hv2znbvdy9-glitch/DEVITO/pull/180
- **Merge-Commit / aktueller Main-Head zum Prüfzeitpunkt:** `365a8244eebe93896086313b2ef1c6c8a446009f`.
- Die Datei `scripts/AVA_SOC_PORTAL_V6_SAFE.ps1` auf `main` enthält die Korrektur; der gelesene Blob-SHA ist `14ac458e104e47dfbaf32d6cc4de5eff5fc66d55`.
- **Post-merge PSScriptAnalyzer:** Run [38579051251](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38579051251), completed / success.
- **Parse-only:** Run [38577253033](https://github.com/hv2znbvdy9-glitch/DEVITO/actions/runs/38577253033), completed / success. Der Test parst die Datei; er führt das SOC-Portal-Skript nicht aus.

### Repository-Run-Sweep (jeweils neueste 5 Runs abgefragt)

- `AVA`: neueste angezeigte Runs sind „Running Copilot cloud agent“ mit Status completed/success; das sind Agent-Läufe und kein Nachweis, dass sämtliche AVA-Workflows oder lokalen Skripte ausgeführt wurden.
- `AVA-007`: Run [37056290532](https://github.com/hv2znbvdy9-glitch/AVA-007/actions/runs/37056290532) `Install and test AVA`, Branch `main`, Commit `6d293b38d1aaea9924b3bc8326f85388f362747e`, ist laut API weiterhin `in_progress` seit 2026-10-02; weitere jüngere gelistete Runs enthalten `failure` bzw. `cancelled`. Das ist als möglicherweise festhängender Lauf zu untersuchen, nicht als Erfolg umzudeuten.
- `DEVITO`: Post-merge PSScriptAnalyzer success wie oben; Parserprüfung zuvor ebenfalls success.
- `Danny`: die neuesten gelisteten Runs sind überwiegend „Running Copilot cloud agent“; ein solcher Lauf ist am 2026-10-10 als failure und ein weiterer als success verzeichnet. Diese Agent-Läufe sind nicht gleichbedeutend mit einem vollständigen Repository-Test.
- `DE.VI.TO`: API meldet `total_count: 0` Workflow-Runs.

### Sicherheits- und Ausführungsgrenzen

- Dies war ein **read-only Statusabruf**. Es wurden durch diesen Sweep keine neuen Workflow-Dispatches ausgelöst.
- `AVA_ADMIN_CHECK.ps1` und `START_AVA_ADMIN_CHECK.cmd` wurden nicht auf einem Windows-Laptop ausgeführt; die vom Nutzer angegebenen Hashes wurden nicht anhand tatsächlicher lokaler Dateien verifiziert.
- Keine Firewall-Regeln entfernt/geändert, keine Scheduled Tasks oder Services verändert, kein AutoDefense-/Rollback-/Punitive-Autoloop ausgeführt.
- Keine Behauptung, alle Repositories oder alle Workflows seien gestartet worden. Der Status von `AVA-007` erfordert eine gezielte Untersuchung des in-progress-Laufs und seiner Logs, bevor ein Retry erwogen wird.

Leitlinie: **Evidenz vor Aktion. Keine erfundenen Runs. Keine Umdeklaration.**
