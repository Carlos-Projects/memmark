# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""CLI interface for MemMark memory integrity toolkit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from memmark.integrity.diff import MemoryDiff
from memmark.scanner import ScanResult, run_full_scan

app = typer.Typer(
    name="memmark",
    help="Memory integrity and watermarking toolkit for AI agent long-term memory systems",
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        from memmark import __version__

        console.print(f"memmark v{__version__}")
        raise typer.Exit()


@app.callback()  # type: ignore[misc]
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """MemMark — AI Agent Memory Integrity Toolkit."""


@app.command()  # type: ignore[misc]
def scan(
    memory_file: Annotated[
        Path,
        typer.Argument(help="Path to memory JSON file or directory"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Write scan results to file (default: stdout)"
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: json | console"),
    ] = "console",
    watermark_key: Annotated[
        str | None,
        typer.Option(
            "--watermark-key",
            "-k",
            help="Secret key for HMAC watermark detection (optional, disables watermark check if omitted)",
        ),
    ] = None,
) -> None:
    """Run all detectors on memory — poisoning, watermark, forensics."""
    try:
        memories = _load_memories(memory_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    result = run_full_scan(
        memories=memories,
        watermark_key=watermark_key,
        metadata={"source": str(memory_file)},
    )

    if format == "json":
        output_text = result.to_json()
        if output:
            output.write_text(output_text, encoding="utf-8")
            console.print(f"[green]Results written to {output}[/green]")
        else:
            typer.echo(output_text)
    else:
        _display_scan_result(result)


@app.command()  # type: ignore[misc]
def watermark(
    memory_file: Annotated[
        Path,
        typer.Argument(help="Path to memory JSON file"),
    ],
    action: Annotated[
        str,
        typer.Option(
            "--action",
            "-a",
            help="Action: inject (embed watermark) | detect (verify) | verify (check provenance)",
        ),
    ] = "detect",
    key: Annotated[
        str | None,
        typer.Option(
            "--key", "-k", help="Secret key for watermark operations (⚠️ required)"
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file for watermarked memory"),
    ] = None,
) -> None:
    """Inject, detect, or verify watermarks in agent memory."""
    from memmark.watermark.detector import WatermarkDetector
    from memmark.watermark.injector import WatermarkInjector

    if not key:
        console.print("[red]Error: --key is required for watermark operations[/red]")
        raise typer.Exit(1)

    try:
        memories = _load_memories(memory_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    if action == "inject":
        injector = WatermarkInjector(secret_key=key)
        watermarked = injector.inject(memories)
        out_path = output or memory_file
        out_path.write_text(
            json.dumps({"memories": watermarked}, indent=2), encoding="utf-8"
        )
        console.print(f"[green]Watermark injected into {out_path}[/green]")
    elif action == "detect":
        detector = WatermarkDetector(secret_key=key)
        results = detector.detect(memories)
        _display_watermark_results(results)
    elif action == "verify":
        detector = WatermarkDetector(secret_key=key)
        results = detector.detect(memories)
        valid = all(r.get("valid", False) for r in results)
        if valid:
            console.print("[green]All watermarks verified successfully[/green]")
        else:
            console.print("[red]Watermark verification failed[/red]")
            raise typer.Exit(1)
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


@app.command()  # type: ignore[misc]
def verify(
    memory_file: Annotated[
        Path,
        typer.Argument(help="Path to memory JSON file"),
    ],
    manifest_file: Annotated[
        Path,
        typer.Option("--manifest", "-m", help="Path to integrity manifest"),
    ],
) -> None:
    """Verify memory integrity against an integrity manifest.

    Compares current SHA-256 hash against the stored manifest hash."""

    from memmark.integrity.manifest import IntegrityManifest
    from memmark.utils.crypto import hash_memory_state

    try:
        memories = _load_memories(memory_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    try:
        manifest = IntegrityManifest.load(manifest_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading manifest: {e}[/red]")
        raise typer.Exit(1)

    current_hash = hash_memory_state(memories)
    if manifest.verify(current_hash):
        console.print("[green]Memory integrity verified — matches manifest[/green]")
    else:
        console.print("[red]INTEGRITY VIOLATION — memory has been modified[/red]")
        console.print(f"  Expected: {manifest.memory_hash}")
        console.print(f"  Current:  {current_hash}")
        raise typer.Exit(1)


@app.command()  # type: ignore[misc]
def manifest(
    memory_file: Annotated[
        Path,
        typer.Argument(help="Path to memory JSON file"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output manifest file"),
    ] = None,
) -> None:
    """Generate integrity manifest for agent memory."""
    from memmark.integrity.manifest import IntegrityManifest

    try:
        memories = _load_memories(memory_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    manifest = IntegrityManifest.create(memories, source=str(memory_file))
    out_path = output or Path(f"memmark-manifest-{manifest.manifest_id[:8]}.json")
    manifest.save(out_path)
    console.print(f"[green]Manifest saved to {out_path}[/green]")
    console.print(f"  Memory hash: {manifest.memory_hash}")
    console.print(f"  Entries: {manifest.entry_count}")


@app.command()  # type: ignore[misc]
def diff(
    memory_before: Annotated[
        Path,
        typer.Argument(help="Path to original memory JSON file"),
    ],
    memory_after: Annotated[
        Path,
        typer.Argument(help="Path to modified memory JSON file"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output diff report file"),
    ] = None,
) -> None:
    """Compare two memory states and detect unauthorized changes."""
    from memmark.integrity.diff import MemoryDiff

    try:
        before = _load_memories(memory_before)
        after = _load_memories(memory_after)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    diff = MemoryDiff.compare(before, after)
    _display_diff(diff)

    if output:
        output.write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Diff report written to {output}[/green]")


def _display_scan_result(result: ScanResult) -> None:
    """Display scan results in Rich console format."""
    summary = result.to_dict()["summary"]

    status_icon = (
        "[green]CLEAN[/green]" if summary["is_clean"] else "[red]ISSUES FOUND[/red]"
    )
    console.print(
        Panel(
            f"Scan ID: {result.scan_id}\n"
            f"Status: {status_icon}\n"
            f"Memory Hash: {result.memory_hash[:16]}...",
            title="MemMark Scan Results",
        ),
    )

    if result.findings:
        table = Table(title="Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Description")
        table.add_column("Memory ID")

        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }

        for finding in result.findings:
            color = severity_colors.get(finding.severity.value, "white")
            table.add_row(
                f"[{color}]{finding.severity.value.upper()}[/{color}]",
                finding.finding_type.value,
                finding.description,
                finding.memory_id or "—",
            )

        console.print(table)


def _display_watermark_results(results: list[dict[str, Any]]) -> None:
    """Display watermark detection results."""
    table = Table(title="Watermark Detection Results")
    table.add_column("Memory ID", style="bold")
    table.add_column("Status")
    table.add_column("Confidence")

    for r in results:
        status = "[green]DETECTED[/green]" if r.get("valid") else "[red]NOT FOUND[/red]"
        table.add_row(
            r.get("memory_id", "unknown"),
            status,
            f"{r.get('confidence', 0):.2%}",
        )

    console.print(table)


def _display_diff(diff: MemoryDiff) -> None:
    """Display memory diff results."""
    d = diff.to_dict()
    console.print(
        Panel(
            f"Entries added: {d.get('added', 0)}\n"
            f"Entries removed: {d.get('removed', 0)}\n"
            f"Entries modified: {d.get('modified', 0)}\n"
            f"Entries unchanged: {d.get('unchanged', 0)}",
            title="Memory Diff Summary",
        ),
    )

    if d.get("added_entries"):
        console.print("\n[yellow]Added entries:[/yellow]")
        for entry in d["added_entries"]:
            console.print(f"  + {entry.get('id', 'unknown')}")

    if d.get("removed_entries"):
        console.print("\n[red]Removed entries:[/red]")
        for entry in d["removed_entries"]:
            console.print(f"  - {entry.get('id', 'unknown')}")


@app.command()  # type: ignore[misc]
def generate_policy(
    memory_file: Annotated[
        Path,
        typer.Argument(help="Path to memory JSON file"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output policy YAML file"),
    ] = None,
    rate_limit: Annotated[
        int,
        typer.Option("--rate-limit", help="Max requests per window"),
    ] = 100,
    rate_window: Annotated[
        int,
        typer.Option("--rate-window", help="Rate limit window in seconds"),
    ] = 60,
) -> None:
    """Generate MCPGuard-compatible protection policy from memory scan."""
    from memmark.policy.generator import MCPGuardPolicy

    try:
        memories = _load_memories(memory_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading memory: {e}[/red]")
        raise typer.Exit(1)

    result = run_full_scan(
        memories=memories,
        metadata={"source": str(memory_file)},
    )

    policy = MCPGuardPolicy.from_scan_result(result, rate_limit, rate_window)
    out_path = output or Path("mcpguard-policy.yaml")
    policy.save(str(out_path))
    console.print(f"[green]Policy saved to {out_path}[/green]")
    if policy.is_restrictive:
        console.print(f"  Block injection: {policy.block_injection}")
        console.print(f"  Block poisoning: {policy.block_poisoning}")
        console.print(f"  Block resource scan: {policy.block_resource_scan}")


def _load_memories(source: Path) -> list[dict[str, Any]]:
    """Load memory entries from a JSON file.

    Args:
        source: Path to memory JSON file.

    Returns:
        List of memory entry dictionaries.

    Raises:
        FileNotFoundError: If file does not exist.
        json.JSONDecodeError: If JSON is invalid.
    """
    from memmark.scanner import MemoryScanner

    return MemoryScanner().load_memory(source)


if __name__ == "__main__":
    app()
