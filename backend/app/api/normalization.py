from fastapi import APIRouter, HTTPException

from app.normalization.mapper import EventMapper, event_fingerprint


router = APIRouter(prefix="/normalize", tags=["normalization"])


@router.post("")
async def normalize(payload: dict):
    event_payload = dict(payload)
    source = event_payload.pop("_source", "api")
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(status_code=400, detail="_source must be a non-empty string")
    try:
        event = EventMapper().map(event_payload, source=source)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "event": event.model_dump(mode="json"),
        "fingerprint": event_fingerprint(event),
    }