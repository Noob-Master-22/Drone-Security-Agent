

import chromadb
from src.models import FrameEvent


chroma_client = chromadb.PersistentClient(path="./chroma_db")


# get_or_create means this is safe to call multiple times
collection = chroma_client.get_or_create_collection(
    name="drone_frames",
    # cosine distance is better than L2 for semantic text similarity
    metadata={"hnsw:space": "cosine"}
)


def index_event(event: FrameEvent) -> None:
    """
    Adds a frame event to the ChromaDB vector index.

    The raw_caption is what gets embedded — it's the richest text
    representation of the frame. We attach structured metadata so
    ChromaDB can filter results by zone, object_type, etc.

    Args:
        event: the FrameEvent to index
    """
    
    doc_id = f"frame_{event.frame_id}"

    
    metadata = {
        "frame_id": event.frame_id,
        "timestamp": event.timestamp,
        "zone": event.zone,
        "object_type": event.object_type,
        "color": event.color or "unknown",
        "vehicle_model": event.vehicle_model or "unknown",
        "action": event.action or "unknown",
        "suspicious": str(event.suspicious)   # ChromaDB metadata must be str/int/float
    }

    try:
        collection.add(
            documents=[event.raw_caption],   # this is what gets embedded and searched
            metadatas=[metadata],
            ids=[doc_id]
        )
    except Exception as e:
       
        print(f"[Indexer] Add failed for {doc_id}, attempting upsert: {e}")
        collection.upsert(
            documents=[event.raw_caption],
            metadatas=[metadata],
            ids=[doc_id]
        )


def semantic_search(query: str, n_results: int = 5, filter_zone: str = None) -> list[dict]:
    
    where_filter = {"zone": {"$eq": filter_zone}} if filter_zone else None

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where=where_filter,
        include=["documents", "metadatas", "distances"]
    )

    
    output = []
    if results["documents"] and results["documents"][0]:
        for i, doc in enumerate(results["documents"][0]):
            output.append({
                "caption": doc,
                "similarity": round(1 - results["distances"][0][i], 3),  # cosine: closer to 1 = more similar
                **results["metadatas"][0][i]
            })

    return output


def get_collection_count() -> int:
    
    return collection.count()