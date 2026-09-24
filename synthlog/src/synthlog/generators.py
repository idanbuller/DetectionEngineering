"""Field generators and the per-event evaluation context.

A field spec in YAML compiles to a Gen. Specs are:

    "Accepted password for {user}"     string: a template
    42 / true / null                   scalar: a constant
    {choice: [a, b]}                   uniform choice
    {choice: {success: 95, fail: 5}}   weighted choice
    {int: [1, 100]}                    or {int: {min: 1, max: 100, dist: lognormal}}
    {float: [0, 1]}                    same options as int, plus {round: 2}
    {bool: 0.3}                        true with probability 0.3
    {ipv4: 10.0.0.0/16}                or a list of CIDRs
    {uuid: true}
    {hex: 16}                          16 hex characters
    {entity: user.name}                attribute of a picked entity; {entity: host.ip, role: src}
    {map: action, values: {success: "...", failure: "..."}, default: "..."}
    {list: <spec>, min: 1, max: 3}
    {value: <anything>}                a constant, even a string containing braces

Any spec may also carry `null_rate: 0.2` (the field is omitted from 20% of events).
"""

from __future__ import annotations

import bisect
import ipaddress
import math
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import wordlists

MISSING = object()  # a field that is absent from the event


class SpecError(ValueError):
    """An invalid spec, with the dotted path to the offending key."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}" if path else message)
        self.path = path


# -- templates ------------------------------------------------------------------

_TEMPLATE_REF = re.compile(r"\{([A-Za-z_@][\w.@-]*)(?::([^{}]*))?\}")


def format_value(value: Any, spec: Optional[str]) -> str:
    if value is MISSING or value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime(spec) if spec else value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if spec:
        try:
            return format(value, spec)
        except (TypeError, ValueError):
            return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class Template:
    """A string with {name} or {name:format} references; {{ and }} are literal braces."""

    def __init__(self, text: str, path: str = "") -> None:
        self.text = text
        self.path = path
        self._parts: List[Tuple[bool, str, Optional[str]]] = []
        pos = 0
        escaped = text.replace("{{", "\0").replace("}}", "\1")
        for m in _TEMPLATE_REF.finditer(escaped):
            self._parts.append((False, escaped[pos : m.start()], None))
            self._parts.append((True, m.group(1), m.group(2)))
            pos = m.end()
        self._parts.append((False, escaped[pos:], None))
        self.refs = [name for is_ref, name, _ in self._parts if is_ref]

    def render(self, lookup: Callable[[str, Optional[str]], str]) -> str:
        out = []
        for is_ref, value, spec in self._parts:
            out.append(lookup(value, spec) if is_ref else value.replace("\0", "{").replace("\1", "}"))
        return "".join(out)

    @property
    def is_constant(self) -> bool:
        return not self.refs


# -- generators -------------------------------------------------------------------


class Gen:
    null_rate = 0.0

    def generate(self, ctx: Context) -> Any:
        raise NotImplementedError

    def __call__(self, ctx: Context) -> Any:
        if self.null_rate and ctx.rng.random() < self.null_rate:
            return MISSING
        return self.generate(ctx)


class Const(Gen):
    def __init__(self, value: Any) -> None:
        self.value = value

    def generate(self, ctx):
        return self.value


class TemplateGen(Gen):
    def __init__(self, template: Template) -> None:
        self.template = template

    def generate(self, ctx):
        return ctx.render(self.template)


class Choice(Gen):
    def __init__(self, values: Sequence[Any], weights: Optional[Sequence[float]] = None) -> None:
        self.values = list(values)
        self.cum = cumulative(weights or [1.0] * len(values))

    def generate(self, ctx):
        return self.values[weighted_index(ctx.rng, self.cum)]


class Number(Gen):
    def __init__(self, lo: float, hi: float, dist: str, integer: bool, rounding: Optional[int]) -> None:
        self.lo, self.hi, self.dist, self.integer, self.rounding = lo, hi, dist, integer, rounding

    def generate(self, ctx):
        rng = ctx.rng
        if self.dist == "uniform":
            x = rng.uniform(self.lo, self.hi) if not self.integer else rng.randint(int(self.lo), int(self.hi))
        elif self.dist == "normal":
            x = rng.gauss((self.lo + self.hi) / 2, (self.hi - self.lo) / 6)
        else:  # lognormal: most values near lo, a long tail towards hi
            span = max(self.hi - self.lo, 1e-9)
            x = self.lo + span * min(rng.lognormvariate(0, 1) / math.e**2, 1.0)
        x = min(max(x, self.lo), self.hi)
        if self.integer:
            return int(round(x))
        return round(x, self.rounding) if self.rounding is not None else x


class BoolGen(Gen):
    def __init__(self, p: float) -> None:
        self.p = p

    def generate(self, ctx):
        return ctx.rng.random() < self.p


class IPv4(Gen):
    def __init__(self, networks: Sequence[ipaddress.IPv4Network]) -> None:
        self.networks = list(networks)

    def generate(self, ctx):
        net = self.networks[ctx.rng.randrange(len(self.networks))] if len(self.networks) > 1 else self.networks[0]
        if net.num_addresses <= 2:
            return str(net.network_address)
        offset = ctx.rng.randrange(1, net.num_addresses - 1)  # skip network and broadcast
        return str(net.network_address + offset)


class UUIDGen(Gen):
    def generate(self, ctx):
        h = f"{ctx.rng.getrandbits(128):032x}"
        h = h[:12] + "4" + h[13:16] + "89ab"[int(h[16], 16) % 4] + h[17:]
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class Hex(Gen):
    def __init__(self, length: int) -> None:
        self.length = length

    def generate(self, ctx):
        return f"{ctx.rng.getrandbits(self.length * 4):0{self.length}x}"


class EntityRef(Gen):
    def __init__(self, entity: str, attr: str, role: str) -> None:
        self.entity, self.attr, self.role = entity, attr, role

    def generate(self, ctx):
        instance = ctx.role(self.role, self.entity)
        return instance.get(self.attr, MISSING)


class MapGen(Gen):
    def __init__(self, source: str, values: Dict[str, Gen], default: Gen) -> None:
        self.source, self.values, self.default = source, values, default

    def generate(self, ctx):
        key = format_value(ctx.get(self.source), None)
        return self.values.get(key, self.default)(ctx)


class ListGen(Gen):
    def __init__(self, item: Gen, lo: int, hi: int) -> None:
        self.item, self.lo, self.hi = item, lo, hi

    def generate(self, ctx):
        values = (self.item(ctx) for _ in range(ctx.rng.randint(self.lo, self.hi)))
        return [v for v in values if v is not MISSING]


# -- compiling specs ----------------------------------------------------------------

_GENERATOR_KEYS = ("choice", "int", "float", "bool", "ipv4", "uuid", "hex", "entity", "map", "list", "value")
_MODIFIERS = {"null_rate", "role", "values", "default", "dist", "round", "min", "max"}


def compile_spec(spec: Any, path: str) -> Gen:
    """Compile one field spec (see module docstring) into a Gen."""
    if isinstance(spec, str):
        t = Template(spec, path)
        gen: Gen = Const(spec.replace("{{", "{").replace("}}", "}")) if t.is_constant else TemplateGen(t)
        return gen
    if spec is None or isinstance(spec, (bool, int, float)):
        return Const(spec)
    if isinstance(spec, list):
        raise SpecError(path, "a list is not a field spec; did you mean {choice: [...]}?")
    if not isinstance(spec, dict):
        raise SpecError(path, f"unsupported spec {spec!r}")

    kinds = [k for k in _GENERATOR_KEYS if k in spec]
    if len(kinds) != 1:
        found = ", ".join(kinds) if kinds else "none"
        raise SpecError(path, f"expected exactly one generator ({', '.join(_GENERATOR_KEYS)}); found {found}")
    kind = kinds[0]
    allowed = {kind} | _MODIFIERS
    unknown = set(spec) - allowed
    if unknown:
        raise SpecError(path, f"unknown key(s) {', '.join(sorted(map(str, unknown)))} for a {kind} generator")

    gen = _BUILDERS[kind](spec, path)
    null_rate = spec.get("null_rate", 0.0)
    if not isinstance(null_rate, (int, float)) or not 0 <= null_rate <= 1:
        raise SpecError(f"{path}.null_rate", "must be a number between 0 and 1")
    gen.null_rate = float(null_rate)
    return gen


def _build_choice(spec, path):
    options = spec["choice"]
    if isinstance(options, dict):
        if not options:
            raise SpecError(f"{path}.choice", "needs at least one option")
        weights = []
        for k, w in options.items():
            if not isinstance(w, (int, float)) or w < 0:
                raise SpecError(f"{path}.choice.{k}", "weight must be a non-negative number")
            weights.append(float(w))
        if not sum(weights):
            raise SpecError(f"{path}.choice", "weights sum to zero")
        return Choice(list(options), weights)
    if isinstance(options, list) and options:
        return Choice(options)
    raise SpecError(f"{path}.choice", "must be a non-empty list or a mapping of value: weight")


def _range(spec, key, path) -> Tuple[float, float, str, Optional[int]]:
    value = spec[key]
    dist = spec.get("dist", "uniform")
    rounding = spec.get("round")
    if isinstance(value, list) and len(value) == 2:
        lo, hi = value
    elif isinstance(value, dict):
        lo, hi = value.get("min"), value.get("max")
        dist = value.get("dist", dist)
        rounding = value.get("round", rounding)
    else:
        lo, hi = spec.get("min"), spec.get("max")
    if not isinstance(lo, (int, float)) or not isinstance(hi, (int, float)) or lo > hi:
        raise SpecError(f"{path}.{key}", "expected [min, max] with min <= max")
    if dist not in ("uniform", "normal", "lognormal"):
        raise SpecError(f"{path}.dist", "must be uniform, normal or lognormal")
    return lo, hi, dist, rounding


def _build_int(spec, path):
    lo, hi, dist, _ = _range(spec, "int", path)
    return Number(lo, hi, dist, integer=True, rounding=None)


def _build_float(spec, path):
    lo, hi, dist, rounding = _range(spec, "float", path)
    return Number(lo, hi, dist, integer=False, rounding=rounding if rounding is not None else 3)


def _build_bool(spec, path):
    p = spec["bool"]
    if p is True:
        p = 0.5
    if not isinstance(p, (int, float)) or not 0 <= p <= 1:
        raise SpecError(f"{path}.bool", "must be a probability between 0 and 1")
    return BoolGen(float(p))


def _build_ipv4(spec, path):
    cidrs = spec["ipv4"]
    cidrs = [cidrs] if isinstance(cidrs, str) else cidrs
    try:
        nets = [ipaddress.IPv4Network(str(c), strict=False) for c in cidrs]
    except (ValueError, TypeError) as exc:
        raise SpecError(f"{path}.ipv4", str(exc)) from None
    if not nets:
        raise SpecError(f"{path}.ipv4", "needs at least one CIDR")
    return IPv4(nets)


def _build_uuid(spec, path):
    return UUIDGen()


def _build_hex(spec, path):
    n = spec["hex"]
    if not isinstance(n, int) or n < 1:
        raise SpecError(f"{path}.hex", "must be a positive length")
    return Hex(n)


def _build_entity(spec, path):
    ref = spec["entity"]
    if not isinstance(ref, str) or "." not in ref:
        raise SpecError(f"{path}.entity", "expected <entity>.<attribute>, e.g. user.name")
    entity, attr = ref.split(".", 1)
    return EntityRef(entity, attr, str(spec.get("role", entity)))


def _build_map(spec, path):
    values = spec.get("values")
    if not isinstance(values, dict):
        raise SpecError(f"{path}.values", "map needs a values mapping")
    compiled = {format_value(k, None): compile_spec(v, f"{path}.values.{k}") for k, v in values.items()}
    default = compile_spec(spec["default"], f"{path}.default") if "default" in spec else Const(MISSING)
    return MapGen(str(spec["map"]), compiled, default)


def _build_list(spec, path):
    lo, hi = spec.get("min", 1), spec.get("max", 3)
    if not isinstance(lo, int) or not isinstance(hi, int) or not 0 <= lo <= hi:
        raise SpecError(path, "list min/max must be integers with 0 <= min <= max")
    return ListGen(compile_spec(spec["list"], f"{path}.list"), lo, hi)


def _build_value(spec, path):
    return Const(spec["value"])


_BUILDERS = {
    "choice": _build_choice,
    "int": _build_int,
    "float": _build_float,
    "bool": _build_bool,
    "ipv4": _build_ipv4,
    "uuid": _build_uuid,
    "hex": _build_hex,
    "entity": _build_entity,
    "map": _build_map,
    "list": _build_list,
    "value": _build_value,
}


# -- evaluation context -------------------------------------------------------------

_BUILTIN_PATTERN = re.compile(r"^(first|last|word|domain|n|hex|digits)$")


class Context:
    """Evaluates one event (or one entity instance): fields are computed on demand,
    so templates and maps can refer to fields declared after them."""

    def __init__(
        self,
        specs: Dict[str, Gen],
        rng,
        pools: Optional[Dict[str, Any]] = None,
        roles: Optional[Dict[str, Dict[str, Any]]] = None,
        preset: Optional[Dict[str, Any]] = None,
        index: int = 0,
    ) -> None:
        self.specs = specs
        self.rng = rng
        self.pools = pools or {}
        self.roles: Dict[str, Dict[str, Any]] = dict(roles or {})
        self.values: Dict[str, Any] = dict(preset or {})
        self.index = index
        self._resolving: List[str] = []

    def get(self, name: str) -> Any:
        if name in self.values:
            return self.values[name]
        if name in self.specs:
            if name in self._resolving:
                cycle = " -> ".join(self._resolving + [name])
                raise SpecError(name, f"circular reference: {cycle}")
            self._resolving.append(name)
            try:
                value = self.specs[name](self)
            finally:
                self._resolving.pop()
            self.values[name] = value
            return value
        if "." in name:
            role, attr = name.split(".", 1)
            if role in self.roles or role in self.pools:
                return self.role(role, role).get(attr, MISSING)
        return MISSING

    def role(self, role: str, entity: str) -> Dict[str, Any]:
        if role not in self.roles:
            pool = self.pools.get(entity)
            if pool is None:
                raise SpecError(role, f"unknown entity {entity!r}")
            self.roles[role] = pool.pick(self.rng)
        return self.roles[role]

    def evaluate(self) -> Dict[str, Any]:
        """All declared fields, in declaration order, without missing ones."""
        out = {}
        for name in self.specs:
            value = self.get(name)
            if value is not MISSING:
                out[name] = value
        return out

    def render(self, template: Template) -> str:
        return template.render(self._lookup)

    def _lookup(self, name: str, spec: Optional[str]) -> str:
        value = self.get(name)
        if value is MISSING and _BUILTIN_PATTERN.match(name):
            return self._builtin(name, spec)
        return format_value(value, spec)

    def _builtin(self, name: str, spec: Optional[str]) -> str:
        rng = self.rng
        if name == "first":
            return rng.choice(wordlists.FIRST)
        if name == "last":
            return rng.choice(wordlists.LAST)
        if name == "word":
            return rng.choice(wordlists.WORDS)
        if name == "domain":
            return rng.choice(wordlists.DOMAINS)
        if name == "n":
            return format(self.index, spec) if spec else str(self.index)
        length = int(spec) if spec and spec.isdigit() else 8
        if name == "hex":
            return f"{rng.getrandbits(length * 4):0{length}x}"
        return "".join(str(rng.randrange(10)) for _ in range(length))  # digits


# -- weighted picking ---------------------------------------------------------------


def cumulative(weights: Sequence[float]) -> List[float]:
    total = 0.0
    out = []
    for w in weights:
        total += w
        out.append(total)
    return out


def weighted_index(rng, cum: List[float]) -> int:
    return min(bisect.bisect_right(cum, rng.random() * cum[-1]), len(cum) - 1)
