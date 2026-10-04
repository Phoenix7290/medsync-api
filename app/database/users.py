from typing import Optional

from fastapi import Depends
from sqlmodel import Session, select

from app.core.security import (
    DUMMY_PASSWORD_HASH,
    generate_mfa_secret,
    hash_password,
    verify_password,
)
from app.database.session import get_session
from app.models.user import PartnerClient, User, UserCreate, UserRole


class UserRepository:
    """Acesso a usuários e clientes M2M via SQLModel (queries sempre parametrizadas)."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_username(self, username: str) -> Optional[User]:
        statement = select(User).where(User.username == username)
        return self.session.exec(statement).first()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        user = self.get_by_username(username)
        if not user:
            verify_password(password, DUMMY_PASSWORD_HASH)  # custo de tempo equivalente
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def create_user(self, user_in: UserCreate) -> User:
        is_admin = user_in.role == UserRole.ADMIN
        user = User(
            username=user_in.username,
            email=user_in.email,
            full_name=user_in.full_name,
            role=user_in.role,
            doctor_crm=user_in.doctor_crm,
            hashed_password=hash_password(user_in.password),
            mfa_enabled=is_admin,
            mfa_secret=generate_mfa_secret() if is_admin else None,
        )
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def get_partner(self, client_id: str) -> Optional[PartnerClient]:
        statement = select(PartnerClient).where(PartnerClient.client_id == client_id)
        return self.session.exec(statement).first()

    def authenticate_partner(self, client_id: str, client_secret: str) -> Optional[PartnerClient]:
        partner = self.get_partner(client_id)
        if not partner:
            verify_password(client_secret, DUMMY_PASSWORD_HASH)
            return None
        if not verify_password(client_secret, partner.client_secret_hash):
            return None
        return partner


def get_user_repository(session: Session = Depends(get_session)) -> UserRepository:
    return UserRepository(session)
