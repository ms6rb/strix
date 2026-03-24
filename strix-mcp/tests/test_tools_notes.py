"""Unit tests for MCP notes tools (no Docker required)."""
import json

import pytest
from unittest.mock import MagicMock
from fastmcp import FastMCP
from strix_mcp.tools import register_tools


def _tool_text(result) -> str:
    """Extract JSON text from a FastMCP ToolResult."""
    return result.content[0].text


class TestNotesTools:
    """Tests for MCP-side notes storage (no Docker required)."""

    @pytest.fixture
    def mcp_with_notes(self):
        """Create a FastMCP instance with tools registered using a mock sandbox."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    @pytest.mark.asyncio
    async def test_create_note_success(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test Note",
            "content": "Some content",
            "category": "findings",
            "tags": ["xss"],
        })))
        assert result["success"] is True
        assert "note_id" in result

    @pytest.mark.asyncio
    async def test_create_note_empty_title(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "",
            "content": "Some content",
        })))
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_create_note_empty_content(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test",
            "content": "  ",
        })))
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_create_note_invalid_category(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test",
            "content": "Content",
            "category": "invalid",
        })))
        assert result["success"] is False
        assert "category" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_list_notes_empty(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert result["success"] is True
        assert result["total_count"] == 0
        assert result["notes"] == []

    @pytest.mark.asyncio
    async def test_list_notes_with_filter(self, mcp_with_notes):
        # Create two notes in different categories
        await mcp_with_notes.call_tool("create_note", {
            "title": "Finding 1", "content": "XSS found", "category": "findings",
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "Question 1", "content": "Is this vuln?", "category": "questions",
        })

        # Filter by category
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"category": "findings"})))
        assert result["total_count"] == 1
        assert result["notes"][0]["title"] == "Finding 1"

    @pytest.mark.asyncio
    async def test_list_notes_search(self, mcp_with_notes):
        await mcp_with_notes.call_tool("create_note", {
            "title": "SQL Injection", "content": "Found in login", "category": "findings",
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "XSS", "content": "Found in search", "category": "findings",
        })

        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"search": "login"})))
        assert result["total_count"] == 1

    @pytest.mark.asyncio
    async def test_list_notes_tag_filter(self, mcp_with_notes):
        await mcp_with_notes.call_tool("create_note", {
            "title": "Note 1", "content": "Content", "tags": ["auth", "critical"],
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "Note 2", "content": "Content", "tags": ["xss"],
        })

        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"tags": ["auth"]})))
        assert result["total_count"] == 1
        assert result["notes"][0]["title"] == "Note 1"

    @pytest.mark.asyncio
    async def test_update_note_success(self, mcp_with_notes):
        create_result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Original", "content": "Original content",
        })))
        note_id = create_result["note_id"]

        update_result = json.loads(_tool_text(await mcp_with_notes.call_tool("update_note", {
            "note_id": note_id, "title": "Updated Title",
        })))
        assert update_result["success"] is True

        # Verify update
        list_result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert list_result["notes"][0]["title"] == "Updated Title"

    @pytest.mark.asyncio
    async def test_update_note_not_found(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("update_note", {
            "note_id": "nonexistent", "title": "New Title",
        })))
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_note_success(self, mcp_with_notes):
        create_result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "To Delete", "content": "Will be deleted",
        })))
        note_id = create_result["note_id"]

        delete_result = json.loads(_tool_text(await mcp_with_notes.call_tool("delete_note", {
            "note_id": note_id,
        })))
        assert delete_result["success"] is True

        # Verify deletion
        list_result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert list_result["total_count"] == 0

    @pytest.mark.asyncio
    async def test_delete_note_not_found(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("delete_note", {
            "note_id": "nonexistent",
        })))
        assert result["success"] is False
        assert "not found" in result["error"].lower()
