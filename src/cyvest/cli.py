"""
Command-line interface for Cyvest.

Provides commands for managing investigations, displaying summaries,
and generating reports.
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console

from cyvest import __version__


def cmd_show(args: argparse.Namespace) -> int:
    """
    Display an investigation from a JSON file.

    Args:
        args: Command arguments

    Returns:
        Exit code
    """
    import json

    # Load the JSON
    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    # For now, just display the JSON structure
    # In a real implementation, we'd reconstruct the Cyvest object
    console = Console()
    console.print(f"[cyan]Investigation loaded from: {args.input}[/cyan]")
    console.print(f"[green]Global Score: {data.get('score', 'N/A')}[/green]")
    console.print(f"[green]Global Level: {data.get('level', 'N/A')}[/green]")
    console.print(f"[yellow]Total Observables: {len(data.get('observables', {}))}[/yellow]")
    console.print(f"[yellow]Total Checks: {sum(len(checks) for checks in data.get('checks', {}).values())}[/yellow]")

    if args.stats:
        console.print("\n[bold]Statistics:[/bold]")
        stats = data.get("stats", {})
        for key, value in stats.items():
            if not isinstance(value, dict):
                console.print(f"  {key}: {value}")

    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    """
    Merge multiple investigations.

    Args:
        args: Command arguments

    Returns:
        Exit code
    """
    console = Console()
    console.print(f"[cyan]Merging {len(args.inputs)} investigation files...[/cyan]")

    # TODO: Implement actual merging logic
    # This would require deserializing JSON back to Cyvest objects
    console.print("[yellow]Merge functionality not yet implemented[/yellow]")

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """
    Display statistics for an investigation.

    Args:
        args: Command arguments

    Returns:
        Exit code
    """
    import json

    console = Console()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    console.print(f"[cyan]Statistics for: {args.input}[/cyan]\n")

    stats = data.get("stats", {})
    console.print("[bold]Overview:[/bold]")
    console.print(f"  Global Score: {data.get('score', 'N/A')}")
    console.print(f"  Global Level: {data.get('level', 'N/A')}")
    console.print(f"  Total Observables: {stats.get('total_observables', 0)}")
    console.print(f"  Total Checks: {stats.get('total_checks', 0)}")
    console.print(f"  Applied Checks: {stats.get('applied_checks', 0)}")
    console.print(f"  Total Threat Intel: {stats.get('total_threat_intel', 0)}")

    if args.detailed:
        console.print("\n[bold]Observables by Type:[/bold]")
        for obs_type, count in stats.get("observables_by_type", {}).items():
            console.print(f"  {obs_type}: {count}")

        console.print("\n[bold]Checks by Scope:[/bold]")
        for scope, count in stats.get("checks_by_scope", {}).items():
            console.print(f"  {scope}: {count}")

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """
    Export an investigation to different formats.

    Args:
        args: Command arguments

    Returns:
        Exit code
    """
    import json

    console = Console()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    output_path = Path(args.output)

    if args.format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Exported to JSON: {output_path}[/green]")

    elif args.format == "markdown":
        # Generate markdown from JSON data
        # For now, write a basic markdown
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Investigation Report\n\n")
            f.write(f"**Score:** {data.get('score', 'N/A')}\n")
            f.write(f"**Level:** {data.get('level', 'N/A')}\n\n")
            f.write("## Statistics\n\n")
            stats = data.get("stats", {})
            for key, value in stats.items():
                if not isinstance(value, dict):
                    f.write(f"- **{key}:** {value}\n")
        console.print(f"[green]Exported to Markdown: {output_path}[/green]")

    return 0


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description="Cyvest - Cybersecurity Investigation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"Cyvest {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Show command
    show_parser = subparsers.add_parser("show", help="Display an investigation")
    show_parser.add_argument("input", help="Input JSON file")
    show_parser.add_argument("--graph", action="store_true", help="Show observable graph")
    show_parser.add_argument("--stats", action="store_true", help="Show statistics")

    # Merge command
    merge_parser = subparsers.add_parser("merge", help="Merge multiple investigations")
    merge_parser.add_argument("inputs", nargs="+", help="Input JSON files to merge")
    merge_parser.add_argument("-o", "--output", required=True, help="Output JSON file")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Display investigation statistics")
    stats_parser.add_argument("input", help="Input JSON file")
    stats_parser.add_argument("-d", "--detailed", action="store_true", help="Show detailed statistics")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export investigation to different formats")
    export_parser.add_argument("input", help="Input JSON file")
    export_parser.add_argument("-o", "--output", required=True, help="Output file")
    export_parser.add_argument(
        "-f",
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format (default: markdown)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate command
    if args.command == "show":
        return cmd_show(args)
    elif args.command == "merge":
        return cmd_merge(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "export":
        return cmd_export(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
