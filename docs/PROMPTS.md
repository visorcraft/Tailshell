# Prompts

Prompts are saved commands that can be run from the UI. They can be shared, tagged, and optionally scoped to specific workspaces.

## Scope vs. Organization

There are two separate concepts:

- **Workspace scope** controls _where a prompt can be used_.
- **Folders** are just _organizational buckets_ for filtering and grouping prompts.

They are not related to each other.

### Workspace scope

In the prompt editor:

- **Any workspace** (checked) → the prompt is **global** and can run in all workspaces.
- **Any workspace** (unchecked) → select one or more workspaces; the prompt only appears/runs there.

### Folders

Folders only affect how prompts are **grouped in the Prompt Library**:

- Each prompt can have **one folder** or **no folder**.
- Folder membership does **not** change permissions, visibility, or workspace scope.
- Folders are **per-user** and only visible to their owner.

### Tags

Tags are separate from folders and allow multi-label filtering:

- A prompt can have **multiple tags**.
- Tags are global per user and used for filtering.

## Quick reference

- **Use workspaces** to control where prompts are available.
- **Use folders** to organize prompts inside the library.
- **Use tags** for multi-label filtering.
