"""
Network graph visualization for Cyvest investigations using pyvis.

Provides interactive HTML network visualization of observables and their relationships.
"""

from __future__ import annotations

import tempfile
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

from cyvest.levels import LEVEL_COLORS, Level
from cyvest.model import ObservableType, RelationshipDirection, RelationshipType

if TYPE_CHECKING:
    from pyvis.network import Network

    from cyvest.cyvest import Cyvest

try:
    from pyvis.network import Network  # type: ignore[assignment]

    PYVIS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency not installed
    Network = None  # type: ignore[assignment]
    PYVIS_AVAILABLE = False


VISUALIZATION_INSTALL_HINT = (
    "Network visualization requires the 'pyvis' optional dependency. "
    'Install via `pip install "cyvest[visualization]"`.'
)


class VisualizationDependencyMissingError(RuntimeError):
    """Raised when the optional visualization extra is not installed."""

    def __init__(self) -> None:
        super().__init__(VISUALIZATION_INSTALL_HINT)


# Pyvis color mapping from Rich color names
PYVIS_COLOR_MAP = {
    "white": "#FFFFFF",
    "green": "#00FF00",
    "cyan": "#00FFFF",
    "bright_green": "#90EE90",
    "yellow": "#FFFF00",
    "orange3": "#FFA500",
    "red": "#FF0000",
}

# Observable type to shape mapping for visual distinction
OBSERVABLE_SHAPES = {
    ObservableType.IPV4: "dot",
    ObservableType.IPV6: "dot",
    ObservableType.DOMAIN: "diamond",
    ObservableType.URL: "diamond",
    ObservableType.EMAIL: "diamond",
    ObservableType.HASH: "square",
    ObservableType.FILE: "square",
    ObservableType.ARTIFACT: "square",
}


def get_node_color(level: Level) -> str:
    """
    Get pyvis-compatible color for a security level.

    Args:
        level: Security level

    Returns:
        Hex color code for pyvis
    """
    rich_color = LEVEL_COLORS.get(level, "white")
    return PYVIS_COLOR_MAP.get(rich_color, "#FFFFFF")


def get_edge_color(direction: RelationshipDirection) -> str:
    """
    Get edge color based on relationship direction.

    Args:
        direction: Relationship direction

    Returns:
        Hex color code for edge
    """
    if direction == RelationshipDirection.OUTBOUND:
        return "#4A90E2"  # Blue for outbound
    elif direction == RelationshipDirection.INBOUND:
        return "#E24A90"  # Pink for inbound
    else:  # BIDIRECTIONAL
        return "#9B59B6"  # Purple for bidirectional


def get_edge_arrows(direction: RelationshipDirection) -> str:
    """
    Get arrow configuration for relationship direction.

    Args:
        direction: Relationship direction

    Returns:
        Arrow configuration string
    """
    if direction == RelationshipDirection.OUTBOUND:
        return "to"
    elif direction == RelationshipDirection.INBOUND:
        return "from"
    else:  # BIDIRECTIONAL
        return "to;from"


def truncate_middle(text: str, max_length: int) -> str:
    """Truncate text in the middle with an ellipsis when exceeding ``max_length``.

    Keeps both the start and end of the string visible for context while
    respecting the provided length budget.
    """
    if max_length < 4 or len(text) <= max_length:
        return text

    reserved = max_length - 3
    head = reserved // 2 + reserved % 2
    tail = reserved - head

    return f"{text[:head]}...{text[-tail:]}"


def generate_network_graph(
    cv: Cyvest,
    output_dir: str | None = None,
    open_browser: bool = True,
    min_level: Level | None = None,
    observable_types: list[ObservableType] | None = None,
    physics: bool = True,
    group_by_type: bool = False,
    max_label_length: int = 60,
    title: str = "Cyvest Investigation Network",
) -> str:
    """
    Generate an interactive network graph visualization of observables and relationships.

    Creates an HTML file with a pyvis network graph showing observables as nodes
    (colored by level, sized by score, shaped by type) and relationships as edges
    (colored by direction, labeled by type).

    Args:
        cv: Cyvest investigation to visualize
        output_dir: Directory to save HTML file (defaults to temp directory)
        open_browser: Whether to automatically open the HTML file in a browser
        min_level: Minimum security level to include (filters out lower levels)
        observable_types: List of observable types to include (filters out others)
        physics: Enable physics simulation for organic layout (default: False for static layout)
        group_by_type: Group observables by type using hierarchical layout (default: False)
        max_label_length: Maximum length for node labels before truncation (default: 60)
        title: Title displayed in the HTML visualization

    Returns:
        Path to the generated HTML file

    Examples:
        >>> from cyvest import Cyvest
        >>> from cyvest.io_visualization import generate_network_graph
        >>> cv = Cyvest()
        >>> # Create investigation with observables
        >>> generate_network_graph(cv)
        '/tmp/cyvest_network_12345.html'
    """
    if not PYVIS_AVAILABLE or Network is None:  # pragma: no branch - both change together
        raise VisualizationDependencyMissingError()

    normalized_min_level = min_level

    # Create pyvis network with physics enabled for organic layout
    net = Network(
        height="800px",
        width="100%",
        bgcolor="#FFFFFF",
        font_color="#1E1E1E",
        directed=True,
    )
    net.heading = title

    # Configure physics and interaction options
    physics_enabled = "true" if physics else "false"

    # Build layout configuration
    if group_by_type:
        layout_config = """
            "layout": {
                "hierarchical": {
                    "enabled": true,
                    "direction": "UD",
                    "sortMethod": "directed",
                    "levelSeparation": 200,
                    "nodeSpacing": 150,
                    "treeSpacing": 200
                }
            },"""
    else:
        layout_config = ""

    net.set_options(
        f"""
    {{
        {layout_config}
        "physics": {{
            "enabled": {physics_enabled},
            "stabilization": {{
                "enabled": true,
                "iterations": 200
            }},
            "barnesHut": {{
                "gravitationalConstant": -8000,
                "centralGravity": 0.3,
                "springLength": 95,
                "springConstant": 0.04,
                "damping": 0.09,
                "avoidOverlap": 0.1
            }}
        }},
        "interaction": {{
            "navigationButtons": false,
            "keyboard": true
        }}
    }}
    """
    )

    # Get all observables
    observables = cv.observable_get_all()

    # Filter observables based on criteria
    filtered_observables = {}
    for key, obs in observables.items():
        # Filter by minimum level
        if normalized_min_level is not None and obs.level < normalized_min_level:
            continue

        # Filter by observable types
        if observable_types is not None and obs.obs_type not in observable_types:
            continue

        filtered_observables[key] = obs

    # Get root observable key for special positioning
    root_key = cv.observable_get_root().key if cv.observable_get_root() else None

    # Add nodes for each observable
    for key, obs in filtered_observables.items():
        # Get color based on level
        color = get_node_color(obs.level)

        # Get shape based on observable type
        shape = OBSERVABLE_SHAPES.get(obs.obs_type, "dot")

        # Build label with type, value, and level
        obs_type_str = obs.obs_type.value if isinstance(obs.obs_type, ObservableType) else str(obs.obs_type)
        obs_value = f"{obs.value}"
        label = truncate_middle(obs_value, max_label_length)

        # Build title (hover text) with detailed info
        title_parts = [
            f"Type: {obs_type_str}",
            f"Value: {obs.value}",
            f"Level: {obs.level.name}",
            f"Score: {obs.score_display}",
            f"Key: {key}",
        ]

        if obs.internal:
            title_parts.append("Internal: Yes")
        if obs.whitelisted:
            title_parts.append("Whitelisted: Yes")
        if obs.threat_intels:
            title_parts.append(f"Threat Intel Sources: {len(obs.threat_intels)}")
        if obs.check_links:
            title_parts.append(f"Linked checks: {len(obs.check_links)}")

        title_text = "\n".join(title_parts)

        # Prepare node options
        node_options = {
            "label": label,
            "title": title_text,
            "color": color,
            "size": 10,
            "shape": shape,
            "font": {"size": 10, "color": "#FFFFFF"},
        }

        # Add group attribute for type-based grouping
        if group_by_type:
            node_options["group"] = obs.obs_type.value

        # Fix root node at center position if physics is disabled
        if key == root_key and not physics:
            node_options["label"] = "ROOT"
            node_options["x"] = 0
            node_options["y"] = 0
            node_options["fixed"] = True
            node_options["size"] = 20  # Make root node slightly larger

        # Add node to network
        net.add_node(key, **node_options)

    # Add edges for relationships
    for key, obs in filtered_observables.items():
        for rel in obs.relationships:
            # Only add edge if target is also in filtered observables
            if rel.target_key not in filtered_observables:
                continue

            # Get edge properties based on direction
            edge_color = get_edge_color(rel.direction)
            arrows = get_edge_arrows(rel.direction)

            # Build edge label
            rel_type_str = (
                rel.relationship_type.value
                if isinstance(rel.relationship_type, RelationshipType)
                else str(rel.relationship_type)
            )
            edge_label = rel_type_str

            # Build edge title (hover text)
            edge_title = f"{rel_type_str}\nDirection: {rel.direction.name}"

            # Add edge to network
            net.add_edge(
                key,
                rel.target_key,
                label=edge_label,
                title=edge_title,
                color=edge_color,
                arrows=arrows,
                font={"size": 8},
            )

    # Determine output path
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="cyvest_")

    output_path = Path(output_dir) / "cyvest_network.html"

    # Save to HTML file
    net.save_graph(str(output_path))

    # Open in browser if requested
    if open_browser:
        webbrowser.open(f"file://{output_path.absolute()}")

    return str(output_path)
