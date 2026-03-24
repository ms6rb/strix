from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP

from .tools_helpers import VALID_NOTE_CATEGORIES


def register_notes_tools(mcp: FastMCP, notes_storage: dict[str, dict[str, Any]]) -> None:

    @mcp.tool()
    async def create_note(
        title: str,
        content: str,
        category: str = "general",
        tags: list[str] | None = None,
    ) -> str:
        """Create a structured note during the scan for tracking findings,
        methodology decisions, questions, or plans.

        title: note title
        content: note body text
        category: general | findings | methodology | questions | plan | recon
        tags: optional list of tags for filtering

        Returns: note_id on success."""
        if not title or not title.strip():
            return json.dumps({"success": False, "error": "Title cannot be empty"})
        if not content or not content.strip():
            return json.dumps({"success": False, "error": "Content cannot be empty"})
        if category not in VALID_NOTE_CATEGORIES:
            return json.dumps({
                "success": False,
                "error": f"Invalid category. Must be one of: {', '.join(VALID_NOTE_CATEGORIES)}",
            })

        note_id = uuid.uuid4().hex[:8]
        timestamp = datetime.now(UTC).isoformat()
        notes_storage[note_id] = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags or [],
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        return json.dumps({
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title.strip()}' created successfully",
        })

    @mcp.tool()
    async def list_notes(
        category: str | None = None,
        tags: list[str] | None = None,
        search: str | None = None,
    ) -> str:
        """List and filter notes created during the scan.

        category: filter by category — general | findings | methodology | questions | plan
        tags: filter by tags (notes matching any tag are returned)
        search: search query to match against note title and content

        Returns: notes list and total_count."""
        filtered = []
        for nid, note in notes_storage.items():
            if category and note.get("category") != category:
                continue
            if tags and not any(t in note.get("tags", []) for t in tags):
                continue
            if search:
                s = search.lower()
                if s not in note.get("title", "").lower() and s not in note.get("content", "").lower():
                    continue
            entry = dict(note)
            entry["note_id"] = nid
            filtered.append(entry)

        filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return json.dumps({"success": True, "notes": filtered, "total_count": len(filtered)})

    @mcp.tool()
    async def update_note(
        note_id: str,
        title: str | None = None,
        content: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Update an existing note's title, content, or tags.

        note_id: the ID returned by create_note
        title: new title (optional)
        content: new content (optional)
        tags: new tags list (optional, replaces existing tags)

        Returns: success status."""
        if note_id not in notes_storage:
            return json.dumps({"success": False, "error": f"Note with ID '{note_id}' not found"})

        note = notes_storage[note_id]
        if title is not None:
            if not title.strip():
                return json.dumps({"success": False, "error": "Title cannot be empty"})
            note["title"] = title.strip()
        if content is not None:
            if not content.strip():
                return json.dumps({"success": False, "error": "Content cannot be empty"})
            note["content"] = content.strip()
        if tags is not None:
            note["tags"] = tags
        note["updated_at"] = datetime.now(UTC).isoformat()

        return json.dumps({
            "success": True,
            "message": f"Note '{note['title']}' updated successfully",
        })

    @mcp.tool()
    async def delete_note(note_id: str) -> str:
        """Delete a note by ID.

        note_id: the ID returned by create_note

        Returns: success status."""
        if note_id not in notes_storage:
            return json.dumps({"success": False, "error": f"Note with ID '{note_id}' not found"})

        title = notes_storage[note_id]["title"]
        del notes_storage[note_id]
        return json.dumps({
            "success": True,
            "message": f"Note '{title}' deleted successfully",
        })
