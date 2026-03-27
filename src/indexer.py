import chromadb
from src.models import FrameEvent

COLLECTION_NAME = "drone_frames"


def make_chroma_client():
    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )
    return client, collection


def index_event(event: FrameEvent, collection) -> None:
    doc_id = f"frame_{event.frame_id}"

    metadata = {
        "frame_id": event.frame_id,
        "timestamp": event.timestamp,
        "zone": event.zone,
        "object_type": event.object_type,
        "color": event.color or "unknown",
        "vehicle_model": event.vehicle_model or "unknown",
        "action": event.action or "unknown",
        "suspicious": str(event.suspicious)
    }

    try:
        collection.add(
            documents=[event.raw_caption],
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


def semantic_search(query: str, collection, n_results: int = 5, filter_zone: str = None) -> list[dict]:
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
                "similarity": round(1 - results["distances"][0][i], 3),
                **results["metadatas"][0][i]
            })

    return output


def get_collection_count(collection) -> int:
    return collection.count()