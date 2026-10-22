from uuid import UUID

from sqlalchemy.orm import Session

from ai_security_platform.storage.models import AuditEvent, Project, ScanRun


def append_project_audit(session: Session, project_id: UUID, request_id: str) -> None:
    session.add(
        AuditEvent(
            event_type="project.created",
            object_type="project",
            object_id=project_id,
            actor="local_operator",
            component="api",
            request_id=request_id,
            event_metadata={},
        )
    )
    session.flush()


def create_project(session: Session, name: str, request_id: str) -> Project:
    with session.begin():
        project = Project(name=name)
        session.add(project)
        session.flush()
        append_project_audit(session, project.id, request_id)
    return project


def get_project(session: Session, project_id: UUID) -> Project | None:
    return session.get(Project, project_id)


def get_scan(session: Session, scan_id: UUID) -> ScanRun | None:
    return session.get(ScanRun, scan_id)
