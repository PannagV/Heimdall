from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


DEFAULT_EVENT_PROJECTION: Dict[str, int] = {
    "_id": 0,
    "event_id": 1,
    "timestamp": 1,
    "event": 1,
    "source": 1,
    "destination": 1,
    "network": 1,
    "alert": 1,
    "incident": 1,
    "source_type": 1,
}


class QuerySyntaxError(ValueError):
    def __init__(self, message: str, position: int = 0):
        super().__init__(message)
        self.message = message
        self.position = max(0, int(position))


@dataclass(frozen=True)
class FieldSpec:
    mongo_path: str
    value_type: str
    operators: frozenset[str]
    sortable: bool = True


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    position: int


@dataclass(frozen=True)
class ConditionNode:
    field: FieldSpec
    operator: str
    value: Any = None


@dataclass(frozen=True)
class LogicalNode:
    operator: str
    terms: Sequence["QueryNode"]


@dataclass(frozen=True)
class NotNode:
    term: "QueryNode"


QueryNode = Union[ConditionNode, LogicalNode, NotNode]


@dataclass(frozen=True)
class ParsedSearchQuery:
    mongo_filter: Dict[str, Any]
    projection: Dict[str, int]
    sort: List[Tuple[str, int]]
    limit: int
    offset: int
    selected_fields: List[str]


def _build_field_specs() -> Dict[str, FieldSpec]:
    string_ops = frozenset({"=", "!=", "LIKE", "IN", "IS NULL", "IS NOT NULL"})
    int_ops = frozenset({"=", "!=", ">", ">=", "<", "<=", "IN", "IS NULL", "IS NOT NULL"})
    array_ops = frozenset({"CONTAINS", "IS NULL", "IS NOT NULL"})

    specs: Dict[str, FieldSpec] = {}

    def register(
        aliases: Sequence[str],
        mongo_path: str,
        value_type: str,
        operators: frozenset[str],
        sortable: bool = True,
    ) -> None:
        spec = FieldSpec(
            mongo_path=mongo_path,
            value_type=value_type,
            operators=operators,
            sortable=sortable,
        )
        for alias in aliases:
            specs[alias.lower()] = spec

    register(("event_id",), "event_id", "string", string_ops)
    register(("timestamp",), "timestamp", "string", string_ops)
    register(("source_type",), "source_type", "string", string_ops)

    register(("kind", "event.kind"), "event.kind", "string", string_ops)
    register(("category", "event.category"), "event.category", "array_string", array_ops, sortable=False)
    register(("type", "event.type"), "event.type", "array_string", array_ops, sortable=False)
    register(("severity", "event.severity"), "event.severity", "int", int_ops)
    register(("outcome", "event.outcome"), "event.outcome", "string", string_ops)

    register(("source.ip", "src_ip"), "source.ip", "string", string_ops)
    register(("source.port", "src_port"), "source.port", "int", int_ops)
    register(("destination.ip", "dst_ip"), "destination.ip", "string", string_ops)
    register(("destination.port", "dst_port"), "destination.port", "int", int_ops)

    register(("network.protocol", "protocol"), "network.protocol", "string", string_ops)
    register(("network.transport", "transport"), "network.transport", "string", string_ops)

    register(("alert.id",), "alert.id", "int", int_ops)
    register(("alert.signature", "signature"), "alert.signature", "string", string_ops)
    register(("alert.category",), "alert.category", "string", string_ops)
    register(("alert.severity",), "alert.severity", "int", int_ops)

    register(("incident.id",), "incident.id", "string", string_ops)
    register(("incident.incident_id", "incident_id"), "incident.incident_id", "string", string_ops)

    return specs


FIELD_SPECS = _build_field_specs()

KEYWORDS = {
    "SELECT",
    "FROM",
    "WHERE",
    "ORDER",
    "BY",
    "ASC",
    "DESC",
    "LIMIT",
    "OFFSET",
    "AND",
    "OR",
    "NOT",
    "LIKE",
    "IN",
    "IS",
    "NULL",
    "CONTAINS",
    "TRUE",
    "FALSE",
}

TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
    |(?P<STRING>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")
    |(?P<OP>>=|<=|!=|=|>|<)
    |(?P<COMMA>,)
    |(?P<LPAREN>\()
    |(?P<RPAREN>\))
    |(?P<STAR>\*)
    |(?P<WORD>[A-Za-z0-9_.:/-]+)
    """,
    re.VERBOSE,
)


def tokenize(query: str) -> List[Token]:
    tokens: List[Token] = []
    idx = 0
    while idx < len(query):
        match = TOKEN_RE.match(query, idx)
        if not match:
            raise QuerySyntaxError(f"Unexpected character '{query[idx]}'", idx)

        kind = match.lastgroup or ""
        value = match.group(0)
        if kind == "WS":
            idx = match.end()
            continue

        if kind == "WORD":
            upper = value.upper()
            if upper in KEYWORDS:
                tokens.append(Token(upper, upper, idx))
            else:
                tokens.append(Token("WORD", value, idx))
        elif kind == "STRING":
            tokens.append(Token("STRING", value, idx))
        elif kind == "OP":
            tokens.append(Token("OP", value, idx))
        else:
            tokens.append(Token(kind, value, idx))

        idx = match.end()

    tokens.append(Token("EOF", "", len(query)))
    return tokens


class QueryParser:
    def __init__(self, tokens: Sequence[Token], default_limit: int, max_limit: int):
        self.tokens = list(tokens)
        self.pos = 0
        self.default_limit = max(1, default_limit)
        self.max_limit = max(1, max_limit)

        self.where: Dict[str, Any] = {}
        self.projection: Dict[str, int] = dict(DEFAULT_EVENT_PROJECTION)
        self.sort: List[Tuple[str, int]] = [("timestamp", -1)]
        self.limit: int = self.default_limit
        self.offset: int = 0
        self.selected_fields: List[str] = []

    def parse(self) -> ParsedSearchQuery:
        if self._match("SELECT"):
            self._parse_select_clause()
        else:
            self._parse_short_form()

        self._expect("EOF", "Unexpected trailing input")
        return ParsedSearchQuery(
            mongo_filter=self.where,
            projection=self.projection,
            sort=self.sort,
            limit=self.limit,
            offset=self.offset,
            selected_fields=self.selected_fields,
        )

    def _parse_select_clause(self) -> None:
        select_fields = self._parse_select_fields()
        self._expect("FROM", "Expected FROM after SELECT")
        table = self._consume("WORD", "Expected table name after FROM")
        if table.value.lower() != "events":
            raise QuerySyntaxError("Only FROM events is supported", table.position)

        if self._match("WHERE"):
            node = self._parse_expression()
            self.where = self._compile_node(node)

        self._parse_tail_clauses()

        if select_fields == ["*"]:
            self.projection = {"_id": 0}
            self.selected_fields = ["*"]
        else:
            projection = {"_id": 0}
            selected: List[str] = []
            for field in select_fields:
                spec = self._resolve_field(field)
                projection[spec.mongo_path] = 1
                selected.append(spec.mongo_path)
            self.projection = projection
            self.selected_fields = selected

    def _parse_short_form(self) -> None:
        if self._current().kind == "WHERE":
            self._advance()
            node = self._parse_expression()
            self.where = self._compile_node(node)
        elif self._current().kind not in {"ORDER", "LIMIT", "OFFSET", "EOF"}:
            node = self._parse_expression()
            self.where = self._compile_node(node)

        self._parse_tail_clauses()

    def _parse_select_fields(self) -> List[str]:
        if self._match("STAR"):
            return ["*"]

        fields: List[str] = []
        while True:
            token = self._consume("WORD", "Expected field name in SELECT")
            self._resolve_field(token.value, token.position)
            fields.append(token.value)
            if not self._match("COMMA"):
                break
        if not fields:
            current = self._current()
            raise QuerySyntaxError("SELECT requires at least one field", current.position)
        return fields

    def _parse_tail_clauses(self) -> None:
        if self._match("ORDER"):
            self._expect("BY", "Expected BY after ORDER")
            self.sort = self._parse_sort_fields()

        if self._match("LIMIT"):
            raw_limit = self._parse_non_negative_int("LIMIT")
            if raw_limit <= 0:
                raise QuerySyntaxError("LIMIT must be greater than 0", self._current().position)
            self.limit = min(raw_limit, self.max_limit)
        else:
            self.limit = min(self.limit, self.max_limit)

        if self._match("OFFSET"):
            self.offset = self._parse_non_negative_int("OFFSET")

    def _parse_sort_fields(self) -> List[Tuple[str, int]]:
        sort_fields: List[Tuple[str, int]] = []
        while True:
            field_token = self._consume("WORD", "Expected sort field")
            spec = self._resolve_field(field_token.value, field_token.position)
            if not spec.sortable:
                raise QuerySyntaxError(
                    f"Field '{field_token.value}' cannot be used in ORDER BY",
                    field_token.position,
                )

            direction = 1
            if self._match("ASC"):
                direction = 1
            elif self._match("DESC"):
                direction = -1

            sort_fields.append((spec.mongo_path, direction))
            if not self._match("COMMA"):
                break

        return sort_fields or [("timestamp", -1)]

    def _parse_expression(self) -> QueryNode:
        return self._parse_or()

    def _parse_or(self) -> QueryNode:
        terms: List[QueryNode] = [self._parse_and()]
        while self._match("OR"):
            terms.append(self._parse_and())
        if len(terms) == 1:
            return terms[0]
        return LogicalNode("OR", terms)

    def _parse_and(self) -> QueryNode:
        terms: List[QueryNode] = [self._parse_not()]
        while self._match("AND"):
            terms.append(self._parse_not())
        if len(terms) == 1:
            return terms[0]
        return LogicalNode("AND", terms)

    def _parse_not(self) -> QueryNode:
        if self._match("NOT"):
            return NotNode(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> QueryNode:
        if self._match("LPAREN"):
            node = self._parse_expression()
            self._expect("RPAREN", "Expected ')' to close grouped expression")
            return node
        return self._parse_condition()

    def _parse_condition(self) -> QueryNode:
        field_token = self._consume("WORD", "Expected field name")
        spec = self._resolve_field(field_token.value, field_token.position)

        if self._match("IS"):
            if self._match("NOT"):
                self._expect("NULL", "Expected NULL after IS NOT")
                return ConditionNode(spec, "IS NOT NULL")
            self._expect("NULL", "Expected NULL after IS")
            return ConditionNode(spec, "IS NULL")

        if self._match("IN"):
            self._expect("LPAREN", "Expected '(' after IN")
            values: List[Any] = []
            while True:
                values.append(self._parse_literal())
                if not self._match("COMMA"):
                    break
            self._expect("RPAREN", "Expected ')' after IN list")
            return ConditionNode(spec, "IN", values)

        if self._match("CONTAINS"):
            value = self._parse_literal()
            return ConditionNode(spec, "CONTAINS", value)

        if self._match("LIKE"):
            value = self._parse_literal()
            return ConditionNode(spec, "LIKE", value)

        op = self._consume("OP", "Expected comparison operator")
        value = self._parse_literal()
        return ConditionNode(spec, op.value, value)

    def _parse_literal(self) -> Any:
        token = self._current()

        if token.kind == "STRING":
            self._advance()
            return self._parse_quoted_string(token)

        if token.kind in {"WORD", "TRUE", "FALSE", "NULL"}:
            self._advance()
            if token.kind == "NULL":
                return None
            if token.kind == "TRUE":
                return True
            if token.kind == "FALSE":
                return False
            if re.fullmatch(r"-?\d+", token.value):
                try:
                    return int(token.value)
                except ValueError:
                    pass
            return token.value

        raise QuerySyntaxError("Expected a literal value", token.position)

    def _resolve_field(self, field_name: str, position: Optional[int] = None) -> FieldSpec:
        spec = FIELD_SPECS.get(field_name.lower())
        if spec is None:
            err_pos = self._current().position if position is None else position
            raise QuerySyntaxError(f"Unknown field '{field_name}'", err_pos)
        return spec

    def _compile_node(self, node: QueryNode) -> Dict[str, Any]:
        if isinstance(node, LogicalNode):
            compiled_terms = [self._compile_node(term) for term in node.terms]
            if node.operator == "AND":
                if len(compiled_terms) == 1:
                    return compiled_terms[0]
                return {"$and": compiled_terms}
            if len(compiled_terms) == 1:
                return compiled_terms[0]
            return {"$or": compiled_terms}

        if isinstance(node, NotNode):
            child = self._compile_node(node.term)
            return {"$nor": [child]}

        operator = node.operator
        if operator not in node.field.operators:
            raise QuerySyntaxError(
                f"Operator '{operator}' is not allowed for field '{node.field.mongo_path}'",
                self._current().position,
            )

        field_path = node.field.mongo_path

        if operator == "IS NULL":
            return {field_path: None}

        if operator == "IS NOT NULL":
            return {field_path: {"$ne": None}}

        if operator == "IN":
            values = node.value if isinstance(node.value, list) else [node.value]
            if not values:
                raise QuerySyntaxError("IN requires at least one value", self._current().position)
            typed_values = [self._coerce_value(node.field, value, operator) for value in values]
            return {field_path: {"$in": typed_values}}

        if operator == "CONTAINS":
            value = self._coerce_value(node.field, node.value, operator)
            return {field_path: value}

        if operator == "LIKE":
            value = self._coerce_value(node.field, node.value, operator)
            pattern = _like_to_regex(value)
            return {field_path: {"$regex": pattern, "$options": "i"}}

        value = self._coerce_value(node.field, node.value, operator)
        if operator == "=":
            return {field_path: value}
        if operator == "!=":
            return {field_path: {"$ne": value}}
        if operator == ">":
            return {field_path: {"$gt": value}}
        if operator == ">=":
            return {field_path: {"$gte": value}}
        if operator == "<":
            return {field_path: {"$lt": value}}
        if operator == "<=":
            return {field_path: {"$lte": value}}

        raise QuerySyntaxError(f"Unsupported operator '{operator}'", self._current().position)

    def _coerce_value(self, field: FieldSpec, raw_value: Any, operator: str) -> Any:
        if raw_value is None:
            raise QuerySyntaxError("NULL can only be used with IS NULL / IS NOT NULL", self._current().position)

        if field.value_type == "int":
            if isinstance(raw_value, bool):
                raise QuerySyntaxError("Boolean values are not valid for integer fields", self._current().position)
            if isinstance(raw_value, int):
                return raw_value
            if isinstance(raw_value, str) and re.fullmatch(r"-?\d+", raw_value):
                return int(raw_value)
            raise QuerySyntaxError(
                f"Field '{field.mongo_path}' expects an integer value",
                self._current().position,
            )

        if field.value_type == "array_string":
            if operator != "CONTAINS":
                raise QuerySyntaxError(
                    f"Field '{field.mongo_path}' only supports CONTAINS for value comparisons",
                    self._current().position,
                )
            return str(raw_value)

        if isinstance(raw_value, bool):
            return "true" if raw_value else "false"
        return str(raw_value)

    def _parse_non_negative_int(self, keyword: str) -> int:
        token = self._consume_any(("WORD", "STRING"), f"Expected integer after {keyword}")
        if token.kind == "STRING":
            value = self._parse_quoted_string(token)
        else:
            value = token.value
        if not re.fullmatch(r"\d+", str(value)):
            raise QuerySyntaxError(f"{keyword} expects a non-negative integer", token.position)
        return int(value)

    def _parse_quoted_string(self, token: Token) -> str:
        quote = token.value[0]
        body = token.value[1:-1]
        body = body.replace(f"\\{quote}", quote)
        body = body.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
        return body

    def _current(self) -> Token:
        return self.tokens[self.pos]

    def _advance(self) -> Token:
        token = self.tokens[self.pos]
        if token.kind != "EOF":
            self.pos += 1
        return token

    def _match(self, kind: str) -> bool:
        if self._current().kind == kind:
            self._advance()
            return True
        return False

    def _expect(self, kind: str, message: str) -> Token:
        token = self._current()
        if token.kind != kind:
            raise QuerySyntaxError(message, token.position)
        return self._advance()

    def _consume(self, kind: str, message: str) -> Token:
        return self._expect(kind, message)

    def _consume_any(self, kinds: Sequence[str], message: str) -> Token:
        token = self._current()
        if token.kind not in kinds:
            raise QuerySyntaxError(message, token.position)
        return self._advance()


def _like_to_regex(value: str) -> str:
    parts: List[str] = ["^"]
    for char in value:
        if char == "%":
            parts.append(".*")
        elif char == "_":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    parts.append("$")
    return "".join(parts)


def parse_event_search_query(
    query_text: str,
    *,
    default_limit: int = 200,
    max_limit: int = 1000,
) -> ParsedSearchQuery:
    query = (query_text or "").strip()
    if not query:
        return ParsedSearchQuery(
            mongo_filter={},
            projection=dict(DEFAULT_EVENT_PROJECTION),
            sort=[("timestamp", -1)],
            limit=max(1, min(default_limit, max_limit)),
            offset=0,
            selected_fields=[],
        )

    tokens = tokenize(query)
    parser = QueryParser(tokens, default_limit=default_limit, max_limit=max_limit)
    return parser.parse()
