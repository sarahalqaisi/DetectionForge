from __future__ import annotations

import re
from dataclasses import dataclass


class ConditionSyntaxError(ValueError):
    pass


TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_.-]*)")
OPERATORS = {"and", "or", "not"}


@dataclass
class ConditionParser:
    expression: str
    selections: dict[str, bool]
    max_tokens: int = 128
    max_depth: int = 16

    def __post_init__(self) -> None:
        self.expression = self.expression.strip()
        if len(self.expression) > 2048:
            raise ConditionSyntaxError("Condition is too long")
        self.tokens = self._tokenize(self.expression)
        self.index = 0

    def _tokenize(self, expression: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(expression):
            match = TOKEN_RE.match(expression, position)
            if not match:
                raise ConditionSyntaxError(f"Unexpected token at position {position}")
            tokens.append(match.group(1))
            position = match.end()
        if len(tokens) > self.max_tokens:
            raise ConditionSyntaxError("Condition contains too many tokens")
        if not tokens:
            raise ConditionSyntaxError("Condition cannot be empty")
        return tokens

    def parse(self) -> bool:
        result = self._or(0)
        if self.index != len(self.tokens):
            raise ConditionSyntaxError(f"Unexpected token: {self.tokens[self.index]}")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ConditionSyntaxError("Unexpected end of condition")
        self.index += 1
        return token

    def _or(self, depth: int) -> bool:
        value = self._and(depth)
        while (self._peek() or "").lower() == "or":
            self._take()
            right = self._and(depth)
            value = value or right
        return value

    def _and(self, depth: int) -> bool:
        value = self._not(depth)
        while (self._peek() or "").lower() == "and":
            self._take()
            right = self._not(depth)
            value = value and right
        return value

    def _not(self, depth: int) -> bool:
        if (self._peek() or "").lower() == "not":
            self._take()
            return not self._not(depth)
        return self._primary(depth)

    def _primary(self, depth: int) -> bool:
        if depth > self.max_depth:
            raise ConditionSyntaxError("Condition nesting is too deep")
        token = self._take()
        if token == "(":
            value = self._or(depth + 1)
            if self._take() != ")":
                raise ConditionSyntaxError("Missing closing parenthesis")
            return value
        lowered = token.lower()
        if token == ")" or lowered in OPERATORS:
            raise ConditionSyntaxError(f"Expected selection, got {token}")
        if token not in self.selections:
            raise ConditionSyntaxError(f"Unknown selection: {token}")
        return bool(self.selections[token])


def evaluate_condition(expression: str, selections: dict[str, bool]) -> bool:
    return ConditionParser(expression, selections).parse()
