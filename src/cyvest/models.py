from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from queue import Queue
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .visitors import Visitor


class Scope(enum.Enum):
    PARSER = 0
    FULL = 1
    HEADER = 2
    MIME_HEADER = 3
    BODY = 4
    ATTACHMENT = 5


class ObsCategory(enum.Enum):
    NETWORK = "network"
    FILE = "file"
    EMAIL = "email"
    HOST = "host"
    PROCESS = "process"
    REGISTRY = "registry"
    OTHER = "other"


class ObsType(enum.Enum):
    def __new__(cls, display_name: str, category: ObsCategory):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        obj.display_name = display_name
        obj.category = category
        return obj

    EMAIL_FROM = ("Email From", ObsCategory.EMAIL)
    URL = ("URL", ObsCategory.NETWORK)
    DOMAIN = ("Domain", ObsCategory.NETWORK)
    IP = ("IPv4", ObsCategory.NETWORK)
    IPV6 = ("IPv6", ObsCategory.NETWORK)
    SHA256 = ("SHA256", ObsCategory.FILE)
    MD5 = ("MD5", ObsCategory.FILE)
    FILE = ("File", ObsCategory.FILE)
    SERVER = ("Server", ObsCategory.HOST)
    ANALYZED_MAIL = ("Analyzed Mail", ObsCategory.EMAIL)
    BODY = ("Body", ObsCategory.EMAIL)
    EMAIL = ("Email", ObsCategory.EMAIL)
    PROCESS = ("Process", ObsCategory.PROCESS)
    COMMAND_LINE = ("Command Line", ObsCategory.PROCESS)
    REGISTRY_KEY = ("Registry Key", ObsCategory.REGISTRY)
    CERTIFICATE = ("Certificate", ObsCategory.NETWORK)
    HOSTNAME = ("Hostname", ObsCategory.HOST)
    SERVICE = ("Service", ObsCategory.HOST)
    GEOLOCATION = ("Geolocation", ObsCategory.NETWORK)
    MAC = ("MAC Address", ObsCategory.NETWORK)
    PHONE_NUMBER = ("Phone Number", ObsCategory.OTHER)
    AWS_ACCOUNT = ("AWS Account", ObsCategory.OTHER)

    @classmethod
    def from_string(cls, value: str, default: ObsType | None = None) -> ObsType | None:
        normalized = value.strip().replace("-", "_").replace(" ", "_").upper()
        return cls.__members__.get(normalized, default)

    def to_string(self) -> str:
        return self.display_name


class Level(enum.IntEnum):
    NONE = 0  # No classification applied.
    TRUSTED = 1  # Explicitly trusted by the system itself.
    INFO = 2
    SAFE = 3  # Whitelisted by an external system.
    NOTABLE = 4
    SUSPICIOUS = 5
    MALICIOUS = 6


MAP_LEVEL_DATA = {
    Level.NONE.name: {
        "stdout_color": "bold",
        "global_name": "NONE",
        "css": "background-color: white; color: black;",
        "global_css": "background-color: white; color: black;",
    },
    Level.TRUSTED.name: {
        "stdout_color": "green",
        "global_name": "INFO",
        "css": "background-color: green; color: white;",
        "global_css": "background-color: white; color: black;",
    },
    Level.INFO.name: {
        "stdout_color": "blue",
        "global_name": "INFO",
        "css": "background-color: white; color: black;",
        "global_css": "background-color: white; color: black;",
    },
    Level.SAFE.name: {
        "stdout_color": "green",
        "global_name": "INFO",
        "css": "background-color: green; color: white;",
        "global_css": "background-color: white; color: black;",
    },
    Level.NOTABLE.name: {
        "stdout_color": "yellow",
        "global_name": "INFO",
        "css": "background-color: #B58B00; color: white;",
        "global_css": "background-color: white; color: black;",
    },
    Level.SUSPICIOUS.name: {
        "stdout_color": "yellow",
        "global_name": "SUSPICIOUS",
        "css": "background-color: orange; color: white;",
        "global_css": "background-color: orange; color: white;",
    },
    Level.MALICIOUS.name: {
        "stdout_color": "red",
        "global_name": "MALICIOUS",
        "css": "background-color: red; color: white;",
        "global_css": "background-color: red; color: white;",
    },
}


def update_full_key(
    local: dict[str, Model],
    remote: dict[str, Model],
    on_add: Callable[[Model], bool],
    on_update: Callable[[Model, Model], bool],
) -> None:
    updated = []
    for key, local_obs in list(local.items()):
        remote_obs = remote.get(key)
        if remote_obs and remote_obs is not local_obs:
            on_update(local_obs, remote_obs)
            updated.append(key)
    to_add = list(set(remote.keys()) - set(updated))
    for remote_obs_full_key in to_add:
        remote_obs = remote[remote_obs_full_key]
        on_add(remote_obs)


def update_all_parents_score(
    node: Observable,
    scored_level_model: ScoredLevelModel,
    seen: set[int],
) -> None:
    # Update onset
    for p in node.observables_parents.values():
        p.update_score(scored_level_model)
        if id(p) not in seen:
            seen.add(id(p))
            update_all_parents_score(p, scored_level_model, seen)


def get_color_level(level: Level | str) -> str:
    current_level = Level[level] if isinstance(level, str) else level
    return MAP_LEVEL_DATA.get(current_level.name, {}).get("stdout_color")


def get_color_score(score: float) -> str:
    if score <= 0.0:
        return "bold"
    if score < 5.0:
        return "yellow"
    return "red"


def get_level_from_score(score: float) -> Level | None:
    # Score-derived promotion starts at TRUSTED; Level.NONE is reserved for explicit assignments.
    if score < 0.0:
        return Level.TRUSTED
    if score == 0.0:
        return Level.INFO
    if score < 3.0:
        return Level.NOTABLE
    if score < 5.0:
        return Level.SUSPICIOUS
    if score >= 5.0:
        return Level.MALICIOUS
    return None


def combine_score_level(
    current_score: float,
    current_level: Level,
    candidate_score: float,
    candidate_level: Level | None,
) -> tuple[float, Level]:
    """Return the consolidated score/level when a new datum is applied."""

    new_score = max(current_score, candidate_score)
    best_level = current_level
    if candidate_level and candidate_level > best_level:
        best_level = candidate_level
    inferred = get_level_from_score(new_score)
    if inferred and inferred > best_level:
        best_level = inferred
    return new_score, best_level


class Model(ABC):
    def __init__(self) -> None:
        super().__init__()
        self.generated_by: set[str] = set()

    @property
    @abstractmethod
    def full_key(self) -> str:
        """Method that accept a visitor"""
        raise NotImplementedError("missing property full_key")

    @abstractmethod
    def accept(self, visitor: Visitor) -> Model:
        """Method that accept a visitor"""
        raise NotImplementedError("missing method visit_observable")

    def update(self, model: Model) -> None:
        self.generated_by.update(model.generated_by)

    def add_generated_by(self, name: str) -> None:
        self.generated_by.add(name)


class ScoredLevelModel(Model):
    def __init__(
        self,
        score: float,
        level: Level | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if details is None:
            details = {}
        super().__init__()
        self._score: float = score
        level_from_score = get_level_from_score(self._score)
        self.level: Level = level if level is not None else level_from_score or Level.INFO
        self.details: dict[str, Any] = details if details else {}

    @property
    def score(self) -> float:
        return self._score

    @score.setter
    def score(self, score: float) -> None:
        level = get_level_from_score(score)
        # If current level is Safe and new level is greater then Safe,
        # The current level should be the new level
        if level is not None:
            if self.level != Level.SAFE or level > Level.SAFE:
                self.level = level
        self._score = score

    def update(self, model: ScoredLevelModel) -> None:
        # Update Model
        super().update(model)
        self.details.update(model.details)
        self.update_score(model)

    def handle_safe(self, model: ScoredLevelModel, is_merge: bool) -> None:
        # If the model used is Safe, and current level is lower then Safe,
        # The current level can be Safe, except for rc & obs reconciliation
        if model.level == Level.SAFE and self.level < Level.SAFE and is_merge is False:
            self.level = Level.SAFE

    def update_score(self, model: ScoredLevelModel, is_merge: bool = False) -> None:
        new_score, new_level = combine_score_level(self.score, self.level, model.score, model.level)
        self._score = new_score
        self.level = new_level
        self.handle_safe(model, is_merge)


class ThreatIntel(ScoredLevelModel):
    def __init__(
        self,
        name: str,
        display_name: str,
        obs_value: str,
        obs_type: ObsType,
        score: float,
        level: Level | None = None,
        comment: str | None = None,
        extra: dict[str, Any] | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(score, level)
        self.name = name
        self.display_name = display_name
        self.obs_type = obs_type
        self.obs_value = obs_value
        self.comment = comment
        self.extra = extra
        self.taxonomies = taxonomies

    def __repr__(self) -> str:
        color_score = get_color_score(self.score)
        color_level = get_color_level(self.level)
        full_str = (
            f"{self.name} -> [{color_score}]{self.score}[/{color_score}] {color_level}{self.level.name}[/{color_level}]"
        )
        return full_str

    @property
    def full_key(self) -> str:
        full_key = f"{self.name}.{self.obs_type.name}.{self.obs_value}"
        return full_key

    def accept(self, visitor: Visitor) -> ThreatIntel:
        return visitor.visit_threat_intel(self)

    def update(self, threat_intel: ThreatIntel) -> None:
        if threat_intel.full_key != self.full_key:
            raise Exception(f"Obs impossible to update. Mismatch key: {threat_intel.full_key} {self.full_key}")
        # Update ScoreModel
        super().update(threat_intel)


class Observable(ScoredLevelModel):
    def __init__(self, obs_type: ObsType, obs_value: str) -> None:
        super().__init__(0.0, Level.INFO)
        self.obs_type = obs_type
        self.obs_value = obs_value
        self.threat_intels: dict[str, ThreatIntel] = {}
        self.whitelisted = False
        self.observables_children: dict[str, Observable] = {}
        self.observables_parents: dict[str, Observable] = {}

    def __repr__(self) -> str:
        color_score = get_color_score(self.score)
        color_level = get_color_level(self.level)
        full_str = f"{self.obs_type.name}.{self.obs_value}"
        more_detail = ""
        if self.whitelisted:
            more_detail = " [green]WHITELISTED[/green]"
        full = f"{full_str} -> [{color_score}]{self.score}[/{color_score}] [{color_level}]{self.level.name}[/{color_level}]{more_detail}"  # noqa
        return full

    @property
    def full_key(self) -> str:
        full_key = f"{self.obs_type.name}.{self.obs_value}"
        return full_key

    def _accept(self, visitor: Visitor, seen: set[int]) -> Observable:
        ref = visitor.visit_observable(self)
        seen.add(id(ref))
        # Visit threat intel
        to_update = {}
        for ti in ref.threat_intels.values():
            ref_ti = ti.accept(visitor)
            if ref_ti is not ti:
                to_update[ti.full_key] = ref_ti
        ref.threat_intels.update(to_update)
        # Visit parent
        to_update = {}
        for parent in list(ref.observables_parents.values()):
            if id(parent) not in seen:
                seen.add(id(parent))
                ref_parent = parent._accept(visitor, seen)
                if ref_parent is not parent:
                    to_update[parent.full_key] = ref_parent
                    update_all_parents_score(ref, ref_parent, set([id(ref)]))
        ref.observables_parents.update(to_update)
        # Visit children
        to_update = {}
        for child in list(ref.observables_children.values()):
            if id(child) not in seen:
                seen.add(id(child))
                ref_child = child._accept(visitor, seen)
                if ref_child is not child:
                    to_update[child.full_key] = ref_child
                    ref.update_score(ref_child)
                    update_all_parents_score(ref, ref_child, set([id(ref)]))
        ref.observables_children.update(to_update)
        return ref

    def accept(self, visitor: Visitor) -> Observable:
        return self._accept(visitor, {id(self)})

    def _update(self, observable: Observable, seen: set[str]) -> None:
        # Lambda functions
        def on_update(local_obj: Observable, update_obj: Observable) -> bool:
            if update_obj.full_key not in seen:
                local_obj._update(update_obj, seen)
                return True
            return False

        def on_add_children(new_obj: Observable) -> bool:
            seen.add(new_obj.full_key)
            self.add_observable_children(new_obj)
            return True

        def on_add_parent(new_obj: Observable) -> bool:
            seen.add(new_obj.full_key)
            self.add_observable_parent(new_obj)
            return True

        # don't update if object is same
        if self is observable:
            return
        # Update model
        self.threat_intels.update(observable.threat_intels)
        # Update ScoreModel
        super().update(observable)
        # Update parent score
        update_all_parents_score(self, observable, {id(self)})
        # Update links & nodes
        update_full_key(self.observables_children, observable.observables_children, on_add_children, on_update)
        update_full_key(self.observables_parents, observable.observables_parents, on_add_parent, on_update)

    def update(self, observable: Observable) -> None:
        if observable.full_key != self.full_key:
            raise Exception(f"Obs impossible to update. Mismatch key: {observable.full_key} {self.full_key}")
        # Update links
        self._update(observable, {self.full_key})

    def add_threat_intel(self, threat_intel: ThreatIntel) -> None:
        name = threat_intel.name
        self.threat_intels[name] = threat_intel
        # Update score
        self.update_score(threat_intel)
        update_all_parents_score(self, threat_intel, {id(self)})

    def attach_intel(
        self,
        *,
        name: str,
        score: float,
        level: Level,
        display_name: str | None = None,
        comment: str | None = None,
        extra: dict[str, Any] | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ThreatIntel:
        intel = ThreatIntel(
            name=name,
            display_name=display_name or name,
            obs_value=self.obs_value,
            obs_type=self.obs_type,
            score=score,
            level=level,
            comment=comment,
            extra=extra,
            taxonomies=taxonomies,
        )
        self.add_threat_intel(intel)
        return intel

    def add_observable_parent(self, observable: Observable) -> Observable:
        full_key = observable.full_key
        exist_obs = self.observables_parents.get(full_key)
        if exist_obs:
            exist_obs.update(observable)
        else:
            exist_obs = observable
            self.observables_parents[full_key] = observable
            observable.observables_children[self.full_key] = self
        # Update score
        update_all_parents_score(self, observable, {id(self)})
        return exist_obs

    def add_observable_children(self, observable: Observable) -> Observable:
        full_key = observable.full_key
        exist_obs = self.observables_children.get(full_key)
        if exist_obs:
            exist_obs.update(observable)
        else:
            exist_obs = observable
            self.observables_children[full_key] = observable
            observable.observables_parents[self.full_key] = self
        # Update score
        self.update_score(observable)
        update_all_parents_score(self, observable, {id(self)})
        return exist_obs

    def add_generated_by(self, name: str) -> None:
        super().add_generated_by(name)
        queue = Queue()
        queue.put_nowait(self)
        seen = set()
        while not queue.empty():
            curr_obs = queue.get_nowait()
            if id(curr_obs) not in seen:
                super(Observable, curr_obs).add_generated_by(name)
                seen.add(id(curr_obs))
                for child in curr_obs.observables_children.values():
                    queue.put_nowait(child)
                for parent in curr_obs.observables_parents.values():
                    queue.put_nowait(parent)


class ContainableSLM(ScoredLevelModel):
    def __init__(
        self,
        path: str,
        scope: Scope | None = None,
        identifier: str | None = None,
        description: str | None = None,
        score: float = 0.0,
        level: Level | None = None,
        details: dict | None = None,
    ) -> None:
        if details is None:
            details = {}
        super().__init__(score, level, details)
        self.path = path
        self.scope = scope
        self.description = description
        self.parent: Container | None = None
        self._identifier = identifier.replace("#", "-") if identifier else None

    @property
    def identifier(self) -> str | None:
        return self._identifier

    @identifier.setter
    def identifier(self, value: str | None) -> None:
        self._identifier = value.replace("#", "-") if value else None

    @property
    def local_key(self) -> str:
        ident = f"#{self.identifier}" if self.identifier else ""
        return f"{self.path}{ident}"

    @property
    def full_key(self) -> str:
        if self.parent is not None:
            base = f"{self.parent.full_key}.{self.path}"
        else:
            if self.scope is None:
                raise Exception(f"No scope is set for {self.path}")
            base = f"{self.scope.name}.{self.path}"
        if self.identifier:
            base = f"{base}#{self.identifier}#"
        return base

    @property
    def short_key(self) -> str:
        ident = f"#{self.identifier}" if self.identifier else ""
        return f"{self.path}{ident}"

    def set_parent(self, container: Container | None) -> None:
        self.parent = container
        if container and self.scope is None:
            self.scope = container.scope

    def update_metadata(self, other: ContainableSLM) -> None:
        if other.description:
            self.description = other.description
        self.details.update(other.details)
        if other.scope is not None:
            self.scope = other.scope


class ResultCheck(ContainableSLM):
    def __init__(
        self,
        path: str,
        scope: Scope | None = None,
        identifier: str | None = None,
        description: str | None = None,
        score: float = 0.0,
        level: Level | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(
            path, scope=scope, identifier=identifier, description=description, score=score, level=level, details=details
        )
        self.observables: dict[str, Observable] = {}

    def __repr__(self) -> str:
        color_score = get_color_score(self.score)
        color_level = get_color_level(self.level)
        full_key = self.full_key
        return (
            f"{full_key} -> [{color_score}]{self.score}[/{color_score}] {color_level}{self.level.name}[/{color_level}]"
        )

    def accept(self, visitor: Visitor) -> ResultCheck:
        ref_rc: ResultCheck = visitor.visit_result_check(self)
        normalized: dict[str, Observable] = {}
        for obs in self.observables.values():
            ref_obs = obs.accept(visitor)
            normalized[ref_obs.full_key] = ref_obs
        ref_rc.observables.update(normalized)
        if normalized:
            for observable in normalized.values():
                ref_rc.update_score(observable)
        return ref_rc

    def merge_from(self, other: ResultCheck) -> ResultCheck:
        self.update_metadata(other)
        for obs in other.observables.values():
            existing = self.observables.get(obs.full_key)
            if existing:
                existing.update(obs)
                merged = existing
            else:
                merged = obs
                self.observables[obs.full_key] = merged
            self.update_score(merged)
        self.update_score(other)
        return self

    def add_observable(self, observable: Observable) -> Observable:
        self.observables[observable.full_key] = observable
        self.update_score(observable)
        return observable

    @classmethod
    def create(
        cls,
        path: str,
        *,
        scope: Scope,
        identifier: str | None = None,
        description: str | None = None,
        level: Level = Level.INFO,
        score: float = 0.0,
        details: dict | None = None,
    ) -> ResultCheck:
        return cls(
            path,
            scope=scope,
            identifier=identifier,
            description=description,
            score=score,
            level=level,
            details=details,
        )

    def add_observable_chain(self, chain: Sequence[dict[str, Any]]) -> Observable:
        if not chain:
            raise ValueError("Observable chain cannot be empty")
        parent: Observable | None = None
        root: Observable | None = None
        for entry in chain:
            obs_type = entry.get("obs_type")
            value = entry.get("value")
            if obs_type is None or value is None:
                raise ValueError("Each chain entry must include 'obs_type' and 'value'")
            observable = Observable(obs_type, value)
            intel_data = entry.get("intel")
            if intel_data:
                observable.attach_intel(**intel_data)
            if parent is None:
                root = self.add_observable(observable)
            else:
                parent.add_observable_children(observable)
            parent = observable
        assert root is not None
        return root

    def add_threat_intel(self, threat_intel: ThreatIntel) -> Observable:
        observable = self.add_observable(Observable(threat_intel.obs_type, threat_intel.obs_value))
        observable.add_threat_intel(threat_intel)
        self.update_score(threat_intel)
        return observable

    def add_generated_by(self, name: str) -> None:
        super().add_generated_by(name)
        for observable in self.observables.values():
            observable.add_generated_by(name)


class Container(ContainableSLM):
    def __init__(
        self,
        path: str,
        scope: Scope | None = None,
        identifier: str | None = None,
        description: str | None = None,
        score: float = 0.0,
        level: Level | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(
            path,
            scope=scope,
            identifier=identifier,
            description=description,
            score=score,
            level=level,
            details=details,
        )
        self.children: list[ContainableSLM] = []
        self._child_keys: set[str] = set()

    def __repr__(self) -> str:
        color_score = get_color_score(self.score)
        color_level = get_color_level(self.level)
        return (
            f"{self.full_key} -> [{color_score}]{self.score}[/{color_score}] "
            f"{color_level}{self.level.name}[/{color_level}] (children={len(self.children)})"
        )

    @property
    def nb_checks(self) -> int:
        count = 0
        for child in self.children:
            if isinstance(child, Container):
                count += child.nb_checks
            else:
                count += 1
        return count

    def attach_child(self, node: ContainableSLM) -> ContainableSLM:
        node.set_parent(self)
        key = node.local_key
        if key in self._child_keys:
            for existing in self.children:
                if existing.local_key == key:
                    if isinstance(existing, Container) and isinstance(node, Container):
                        existing.merge_from(node)
                        return existing
                    if isinstance(existing, ResultCheck) and isinstance(node, ResultCheck):
                        existing.merge_from(node)
                        return existing
                    return existing
        self.children.append(node)
        self._child_keys.add(key)
        return node

    def merge_from(self, other: Container) -> Container:
        self.update_metadata(other)
        for child in other.children:
            self.attach_child(child)
        self.recompute()
        return self

    def contain(self, node: ResultCheck | Container) -> ResultCheck | Container:
        if not isinstance(node, (ResultCheck, Container)):
            raise TypeError("Containers can only hold ResultCheck or Container instances")
        if self.scope is not None and node.scope is not None and node.scope != self.scope:
            raise ValueError(f"Scope doesn't match: {node.scope} with container {self.scope}")
        node.set_parent(self)
        attached = self.attach_child(node)
        return attached

    def recompute(self) -> None:
        total = 0.0
        highest = self.level or Level.INFO
        for child in self.children:
            if isinstance(child, Container):
                child.recompute()
            total += child.score
            if child.level > highest:
                highest = child.level
        self._score = total
        self.level = highest

    def accept(self, visitor: Visitor) -> Container:
        ref_container: Container = visitor.visit_container(self)
        for child in self.children:
            child.accept(visitor)
        return ref_container


class Enrichment(Model):
    def __init__(self, ref_struct: dict, key: str, data: Any) -> None:
        super().__init__()
        self.ref_struct = ref_struct
        self.key = key
        self.data = data

    def __repr__(self) -> str:
        ref = id(self.ref_struct)
        full = f"ENRICHMENT.{ref}.{self.key}"
        return full

    @property
    def full_key(self) -> str:
        full = f"ENRICHMENT.{self.scope.name}.{self.path}"
        return full

    def accept(self, visitor):
        visitor.visit_enrichment(self)

    def update(self, enrichment: Enrichment):
        self.ref_struct = enrichment.ref_struct
        self.key = enrichment.key
        self.data = enrichment.data
