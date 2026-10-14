"""Is an element hidden? Read from its attributes and inline style only.

Part 2: HTML preprocessing pipeline.

Why: scam pages hide things - keyword stuffing for search engines, hidden
inputs that carry tracking data, invisible iframes. Part 2 only RECORDS what
is hidden (hidden_text, input.hidden, embedded.hidden); Parts 3/5 decide what
it means. Without running a browser we can only see what the HTML itself
says, so these checks look at:

- the ``hidden`` attribute and ``aria-hidden="true"``
- inline ``style="..."``: display:none, visibility:hidden|collapse,
  opacity:0, font-size:0

CSS rules in <style> blocks or external stylesheets (``.x {display:none}``)
are not evaluated - that would need a CSS engine. This limit is documented
for the viva and the thesis.
"""

from __future__ import annotations

import re

from bs4 import Tag

ZERO = re.compile(r"^[+-]?0*\.?0*(px|em|rem|pt|%|vh|vw)?$")


def inline_style(tag: Tag) -> dict[str, str]:
    """``style="Display: NONE !important; color:red"`` -> {"display": "none", "color": "red"}."""
    style = tag.get("style")
    if not style or not isinstance(style, str):
        return {}
    result = {}
    for declaration in style.split(";"):
        name, colon, value = declaration.partition(":")
        if colon:
            value = value.lower().replace("!important", "").strip()
            result[name.strip().lower()] = value
    return result


def is_zero(value: str | None) -> bool:
    """'0', '0px', '0.0', '.0em', '0%' -> True."""
    return bool(value) and bool(ZERO.match(value.replace(" ", ""))) and any(c == "0" for c in value)


def hidden_by_style(style: dict[str, str]) -> bool:
    return (
        style.get("display") == "none"
        or style.get("visibility") in ("hidden", "collapse")
        or is_zero(style.get("opacity"))
        or is_zero(style.get("font-size"))
    )


def is_hidden_element(tag: Tag) -> bool:
    """True if this element itself is hidden (its children are then hidden too)."""
    if tag.has_attr("hidden"):
        return True
    if str(tag.get("aria-hidden", "")).strip().lower() == "true":
        return True
    return hidden_by_style(inline_style(tag))


def is_hidden_in_tree(
    tag: Tag, stop_at: Tag | None = None, cache: dict[int, bool] | None = None
) -> bool:
    """True if the element or any ancestor (up to ``stop_at``) is hidden.

    ``cache`` (one dict per page, keyed by ``id(element)``) remembers the answer
    for every element on the walked path. Without it, a deeply nested page with
    thousands of inputs walks the same ancestors again for every input
    (quadratic - a 1 MB page took seconds). Not used together with ``stop_at``.
    """
    use_cache = cache is not None and stop_at is None
    path = []
    result = False
    node = tag
    while isinstance(node, Tag) and node.name != "[document]":
        if use_cache and id(node) in cache:
            result = cache[id(node)]  # the path below is visible itself -> same answer
            break
        path.append(node)
        if is_hidden_element(node):
            result = True
            break
        if node is stop_at:
            break
        node = node.parent
    if use_cache:
        for visited in path:
            cache[id(visited)] = result
    return result


def zero_size(tag: Tag) -> bool:
    """width or height of 0, from the attributes or the inline style (iframes, embeds)."""
    style = inline_style(tag)
    return any(
        is_zero(str(value).strip().lower()) if value is not None else False
        for value in (tag.get("width"), tag.get("height"), style.get("width"), style.get("height"))
    )
