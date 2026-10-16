import logging
import time
from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import IndexModel, ASCENDING, DESCENDING
from app.config import settings

logger = logging.getLogger("phishguard.mongodb")

class MongoDBManager:
    """
    Manages asynchronous MongoDB connection lifecycle, indexing, and health checks.
    Supports MongoDB Atlas cloud clusters and local development instances.
    """

    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self._connected: bool = False
        self._last_error: Optional[str] = None
        self._is_atlas: bool = False

    async def connect(self) -> bool:
        """
        Initializes connection to MongoDB Atlas or local MongoDB instance,
        verifies connectivity via ping, and configures required indexes.
        """
        uri = settings.MONGODB_URI
        if not uri:
            self._last_error = "MONGODB_URI environment variable is not configured."
            logger.error(self._last_error)
            return False

        self._is_atlas = "mongodb+srv://" in uri or "mongodb.net" in uri

        try:
            logger.info(f"Connecting to MongoDB ({'Atlas Cloud' if self._is_atlas else 'Local/Standard'})...")
            # Create async client with bounded timeouts
            self.client = AsyncIOMotorClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=10000,
                maxPoolSize=50,
                minPoolSize=5
            )
            self.db = self.client[settings.MONGODB_DATABASE]

            # Verify connection with an administrative ping
            t0 = time.time()
            await self.client.admin.command('ping')
            latency = (time.time() - t0) * 1000
            self._connected = True
            self._last_error = None
            logger.info(f"MongoDB connection established to database '{settings.MONGODB_DATABASE}' in {latency:.1f}ms.")

            # Create collections and indexes
            await self._create_indexes()
            return True
        except Exception as e:
            self._connected = False
            self._last_error = str(e)
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False

    async def close(self) -> None:
        """
        Gracefully closes the database connection pool.
        """
        if self.client:
            self.client.close()
            self._connected = False
            logger.info("MongoDB connection pool closed.")

    async def check_health(self) -> Dict[str, Any]:
        """
        Executes a real-time health check against the MongoDB instance.
        """
        if not self.client or not self._connected:
            return {
                "status": "disconnected",
                "database": settings.MONGODB_DATABASE,
                "is_atlas": self._is_atlas,
                "error": self._last_error or "Database client uninitialized."
            }

        try:
            t0 = time.time()
            ping_result = await self.client.admin.command('ping')
            latency_ms = round((time.time() - t0) * 1000, 2)
            return {
                "status": "connected",
                "database": settings.MONGODB_DATABASE,
                "is_atlas": self._is_atlas,
                "latency_ms": latency_ms,
                "ping": ping_result.get("ok", 1) == 1
            }
        except Exception as e:
            self._connected = False
            self._last_error = str(e)
            return {
                "status": "unhealthy",
                "database": settings.MONGODB_DATABASE,
                "is_atlas": self._is_atlas,
                "error": str(e)
            }

    async def _create_indexes(self) -> None:
        """
        Ensures appropriate performance and uniqueness indexes.
        """
        try:
            # 1. Users collection indexes: unique normalized email
            users_col = self.get_users_col()
            await users_col.create_indexes([
                IndexModel([("email", ASCENDING)], unique=True, name="idx_user_email_unique"),
                IndexModel([("created_at", DESCENDING)], name="idx_user_created_at")
            ])

            # 2. Investigations collection indexes: unique id, compound (owner_id, created_at)
            inv_col = self.get_investigations_col()
            await inv_col.create_indexes([
                IndexModel([("id", ASCENDING)], unique=True, name="idx_inv_id_unique"),
                IndexModel([("owner_id", ASCENDING), ("created_at", DESCENDING)], name="idx_inv_owner_created"),
                IndexModel([("risk.overall_rating", ASCENDING)], name="idx_inv_rating"),
                IndexModel([("review_status", ASCENDING)], name="idx_inv_review_status")
            ])

            # 3. Audit events collection indexes
            audit_col = self.get_audit_col()
            await audit_col.create_indexes([
                IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)], name="idx_audit_user_time"),
                IndexModel([("event_type", ASCENDING)], name="idx_audit_event_type")
            ])

            logger.info("MongoDB indexes verified successfully.")
        except Exception as e:
            logger.warning(f"Error creating indexes (may already exist): {e}")

    # Accessor helper properties
    def get_users_col(self) -> AsyncIOMotorCollection:
        if self.db is None:
            raise RuntimeError("MongoDB is not connected. Call connect() first.")
        return self.db["users"]

    def get_investigations_col(self) -> AsyncIOMotorCollection:
        if self.db is None:
            raise RuntimeError("MongoDB is not connected. Call connect() first.")
        return self.db["investigations"]

    def get_audit_col(self) -> AsyncIOMotorCollection:
        if self.db is None:
            raise RuntimeError("MongoDB is not connected. Call connect() first.")
        return self.db["audit_events"]

    @property
    def is_connected(self) -> bool:
        return self._connected

# Global singleton database manager
db_manager = MongoDBManager()
