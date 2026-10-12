"""ParsedPage: the structured output of the HTML preprocessing pipeline.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FormInfo(BaseModel):
    """A single <form> and its inputs."""

    action: str | None = None
    method: str | None = None
    input_types: list[str] = Field(default_factory=list)
    input_names: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)


class ScriptInfo(BaseModel):
    """An inline script body or an external script reference."""

    inline: bool
    src: str | None = None
    content: str | None = None


class ParsedPage(BaseModel):
    """Everything later stages need from one HTML page."""

    url: str | None = None
    title: str | None = None
    headings: list[str] = Field(default_factory=list)
    paragraphs: list[str] = Field(default_factory=list)
    buttons: list[str] = Field(default_factory=list)
    visible_text: str = ""
    forms: list[FormInfo] = Field(default_factory=list)
    scripts: list[ScriptInfo] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    iframes: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
