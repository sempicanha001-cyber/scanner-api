from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/me")
async def get_me():
    # Auth is handled via middleware, but this can return detailed profile
    return {"message": "Authenticated"}
