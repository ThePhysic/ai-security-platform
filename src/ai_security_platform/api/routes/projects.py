from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.projects import ProjectCreate, ProjectRead
from ai_security_platform.storage import repositories

router = APIRouter(prefix="/api/v1/projects", dependencies=[Depends(bearer_scheme)])
Database = Annotated[Session, Depends(get_session)]


@router.post("", status_code=201, response_model=ProjectRead)
def create_project(body: ProjectCreate, request: Request, session: Database) -> ProjectRead:
    project = repositories.create_project(session, body.name, request.state.request_id)
    return ProjectRead.model_validate(project)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: UUID, session: Database) -> ProjectRead:
    project = repositories.get_project(session, project_id)
    if project is None:
        raise ApiError(404, "not_found", "Project not found")
    return ProjectRead.model_validate(project)
