from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from rag.embedding import create_embedding
from rag.qdrant_manager import QdrantManager


LOGGER = logging.getLogger(__name__)

RUNBOOK_DIRECTORY = (
    Path(__file__).resolve().parent
    / "docs"
)


def iter_runbook_files(
    directory: Path,
) -> Iterable[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(
            f"Runbook folder not found: {directory}"
        )

    yield from sorted(
        directory.glob("runbook-*.md")
    )


def ingest_runbooks() -> None:
    qdrant = QdrantManager()

    qdrant.recreate_collection()

    files = list(
        iter_runbook_files(
            RUNBOOK_DIRECTORY
        )
    )

    if not files:
        raise RuntimeError(
            f"No runbook files found in: {RUNBOOK_DIRECTORY}"
        )

    inserted = 0

    for doc_id, path in enumerate(
        files,
        start=1,
    ):
        content = path.read_text(
            encoding="utf-8"
        ).strip()

        if not content:
            LOGGER.warning(
                "Skipping empty runbook: %s",
                path.name,
            )
            continue

        vector = create_embedding(
            content
        )

        qdrant.insert_document(
            doc_id=doc_id,
            vector=vector,
            payload={
                "file": path.name,
                "content": content,
                "source_path": str(path),
                "document_type": "runbook",
            },
        )

        inserted += 1

        print(
            f"Ingested: {path.name}"
        )

    if inserted == 0:
        raise RuntimeError(
            "No runbooks were inserted into Qdrant."
        )

    print()
    print(
        f"Successfully ingested {inserted} runbooks."
    )


def main() -> None:
    ingest_runbooks()


if __name__ == "__main__":
    main()