I'll start by reading the repository files as instructed.

**Tool: Bash**
```json
{
  "command": "ls -la && echo \"---CLAUDE.md---\" && cat CLAUDE.md",
  "description": "List repo root and read CLAUDE.md"
}
```

**Tool: Bash**
```json
{
  "command": "find research task state -type f 2>/dev/null | head -50 && echo \"---sizes---\" && find research task state -type f -exec wc -c {} \\; 2>/dev/null | head -50",
  "description": "Inventory KB files and sizes"
}
```