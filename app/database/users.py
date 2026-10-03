from typing import Dict, List, Optional
from app.core.security import hash_password, verify_password
from app.models.user import UserCreate, UserInDB, UserRole


class PartnerClient:
    def __init__(self, client_id: str, client_secret_hash: str, allowed_scopes: List[str]):
        self.client_id = client_id
        self.client_secret_hash = client_secret_hash
        self.allowed_scopes = allowed_scopes


class UserMemoryRepository:
    def __init__(self) -> None:
        self._users: Dict[str, UserInDB] = {}
        self._partners: Dict[str, PartnerClient] = {}
        self._next_id: int = 5
        self._seed_users()

    def _seed_users(self) -> None:
        admin = UserInDB(
            id=1,
            username="admin",
            email="admin@medsync.com",
            role=UserRole.ADMIN,
            full_name="Administrador Geral",
            hashed_password=hash_password("Admin@123"),
            mfa_enabled=True,
            mfa_secret="849201",
        )
        doc1 = UserInDB(
            id=2,
            username="dr_roberto",
            email="roberto@medsync.com",
            role=UserRole.DOCTOR,
            full_name="Dr. Roberto Silva",
            doctor_crm="CRM/SP 123456",
            hashed_password=hash_password("Doctor@123"),
            mfa_enabled=False,
        )
        doc2 = UserInDB(
            id=3,
            username="dra_beatriz",
            email="beatriz@medsync.com",
            role=UserRole.DOCTOR,
            full_name="Dra. Beatriz Santos",
            doctor_crm="CRM/SP 654321",
            hashed_password=hash_password("Doctor@456"),
            mfa_enabled=False,
        )
        rec = UserInDB(
            id=4,
            username="recepcao",
            email="recepcao@medsync.com",
            role=UserRole.RECEPTIONIST,
            full_name="Operador da Recepção",
            hashed_password=hash_password("Recepcao@123"),
            mfa_enabled=False,
        )

        self._users = {
            admin.username: admin,
            doc1.username: doc1,
            doc2.username: doc2,
            rec.username: rec,
        }

        lab_client = PartnerClient(
            client_id="partner-lab-01",
            client_secret_hash=hash_password("LabSecretKey2026!"),
            allowed_scopes=["appointments:read_slots"],
        )
        self._partners = {
            lab_client.client_id: lab_client,
        }

    def get_by_username(self, username: str) -> Optional[UserInDB]:
        return self._users.get(username)

    def get_partner(self, client_id: str) -> Optional[PartnerClient]:
        return self._partners.get(client_id)

    def verify_partner_credentials(self, client_id: str, client_secret: str) -> bool:
        partner = self.get_partner(client_id)
        if not partner:
            return False
        return verify_password(client_secret, partner.client_secret_hash)

    def create_user(self, user_in: UserCreate) -> UserInDB:
        user_id = self._next_id
        self._next_id += 1
        new_user = UserInDB(
            id=user_id,
            username=user_in.username,
            email=user_in.email,
            role=user_in.role,
            full_name=user_in.full_name,
            doctor_crm=user_in.doctor_crm,
            hashed_password=hash_password(user_in.password),
            mfa_enabled=(user_in.role == UserRole.ADMIN),
            mfa_secret="849201" if user_in.role == UserRole.ADMIN else None,
        )
        self._users[new_user.username] = new_user
        return new_user


user_repository = UserMemoryRepository()


def get_user_repository() -> UserMemoryRepository:
    return user_repository
