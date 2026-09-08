I'll start with Phase 0 — reading the mandated methodology, then work the research streams.

`​`​`

**Phase 0 — Methodology ingestion**


<invoke name="Bash">
<parameter name="command">ls -la ~/.lava-workbench/deep-research/ 2>&1 | head -40; echo "---"; ls -la ~/.lava-workbench/deep-research/commands ~/.lava-workbench/deep-research/skills ~/.lava-workbench/deep-research/agents 2>&1 | head -60</parameter>
</invoke>


total 25
drwxr-xr-x 1 anmol 197609    0 Nov 26 17:20 .
drwxr-xr-x 1 anmol 197609    0 Nov 26 18:20 ..
-rw-r--r-- 1 anmol 197609 1096 Nov 26 17:20 CHANGELOG.md
-rw-r--r-- 1 anmol 197609 1067 Nov 26 17:20 README.md
drwxr-xr-x 1 anmol 197609    0 Nov 26 17:20 agents
drwxr-xr-x 1 anmol 197609    0 Nov 26 17:20 commands
drwxr-xr-x 1 anmol 197609    0 Nov 26 17:20 skills
---
/home/anmol/.lava-workbench/deep-research/agents:
total 41
drwxr-xr-x 1 anmol 197609     0 Nov 26 17:20 .
drwxr-xr-x 1 anmol 197609     0 Nov 26 17:20 0.6666666666666666
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 deep-research-agent.md
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 research-agent.md
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 critic-agent.md
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 fact-check-agent.md
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 deep-research-agent.md
-rw-r--r-- 1 anmol 197609  7719 Nov 26 17:20 deep-research-agent.md
</parameter>
</invoke>