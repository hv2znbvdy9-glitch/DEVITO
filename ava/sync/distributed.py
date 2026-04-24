"""Distributed multi-instance synchronization for AVA."""

import asyncio
import uuid
from typing import Dict, Any, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from ava.core.logging import logger


class SyncEventType(Enum):
    """Types of sync events."""

    TASK_CREATED = "task_created"
    TASK_UPDATED = "task_updated"
    TASK_COMPLETED = "task_completed"
    TASK_DELETED = "task_deleted"
    INSTANCE_JOINED = "instance_joined"
    INSTANCE_LEFT = "instance_left"


@dataclass
class SyncEvent:
    """Distributed sync event."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: SyncEventType = SyncEventType.TASK_CREATED
    timestamp: datetime = field(default_factory=datetime.now)
    source_instance: str = ""
    target_instances: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    version: int = 1
    processed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_instance": self.source_instance,
            "target_instances": self.target_instances,
            "data": self.data,
            "version": self.version,
            "processed": self.processed,
        }


class DistributedLock:
    """Simple distributed lock using version numbers."""

    def __init__(self):
        """Initialize lock."""
        self.locks: Dict[str, int] = {}
        self.lock = asyncio.Lock()

    async def acquire(self, key: str, version: int) -> bool:
        """Try to acquire lock."""
        async with self.lock:
            if key not in self.locks or self.locks[key] < version:
                self.locks[key] = version
                return True
        return False

    async def release(self, key: str) -> None:
        """Release lock."""
        async with self.lock:
            if key in self.locks:
                del self.locks[key]


class MultiInstanceSync:
    """Synchronize AVA across multiple instances."""

    def __init__(self, instance_id: str):
        """Initialize multi-instance sync.

        Args:
            instance_id: Unique instance identifier
        """
        self.instance_id = instance_id
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.processed_events: Dict[str, bool] = {}
        self.known_instances: Dict[str, dict] = {}
        self.distributed_lock = DistributedLock()
        self.sync_listeners: List[callable] = []
        logger.info(f"Multi-instance sync initialized for instance: {instance_id}")

    async def register_instance(self, instance_id: str, metadata: Dict[str, Any]) -> None:
        """Register a known instance.

        Args:
            instance_id: Instance ID
            metadata: Instance metadata
        """
        self.known_instances[instance_id] = {
            "id": instance_id,
            "registered_at": datetime.now().isoformat(),
            "metadata": metadata,
            "status": "active",
        }

        event = SyncEvent(
            event_type=SyncEventType.INSTANCE_JOINED,
            source_instance=self.instance_id,
            target_instances=list(self.known_instances.keys()),
            data={"instance_id": instance_id},
        )
        await self.event_queue.put(event)
        logger.info(f"Instance registered: {instance_id}")

    async def publish_event(
        self, event_type: SyncEventType, data: Dict[str, Any], target_instances: List[str] = None
    ) -> str:
        """Publish a sync event.

        Args:
            event_type: Type of event
            data: Event data
            target_instances: Instances to sync to (None = all)

        Returns:
            Event ID
        """
        targets = target_instances or list(self.known_instances.keys())

        event = SyncEvent(
            event_type=event_type,
            source_instance=self.instance_id,
            target_instances=targets,
            data=data,
            version=len(self.processed_events) + 1,
        )

        await self.event_queue.put(event)
        logger.debug(f"Sync event published: {event.event_type.value}")
        return event.id

    async def process_event(self, event: SyncEvent) -> bool:
        """Process a sync event with conflict resolution.

        Args:
            event: Event to process

        Returns:
            True if processed successfully
        """
        # Check if already processed
        if event.id in self.processed_events:
            return False

        # Acquire distributed lock
        lock_key = f"event:{event.data.get('id', 'unknown')}"
        if not await self.distributed_lock.acquire(lock_key, event.version):
            logger.warning(f"Failed to acquire lock for {lock_key}")
            return False

        try:
            # Timestamp-based conflict resolution
            if "timestamp" in event.data:
                event_ts = datetime.fromisoformat(event.data["timestamp"])
                logger.debug(f"Processing event from {event_ts.isoformat()}")

            self.processed_events[event.id] = True
            event.processed = True

            # Notify listeners
            for listener in self.sync_listeners:
                try:
                    await listener(event)
                except Exception as e:
                    logger.error(f"Error in sync listener: {e}")

            logger.info(f"Event processed successfully: {event.id}")
            return True
        finally:
            await self.distributed_lock.release(lock_key)

    async def consumer_loop(self) -> None:
        """Continuously consume and process sync events."""
        logger.info(f"Starting sync consumer loop for {self.instance_id}")

        while True:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=5.0)

                if event.source_instance == self.instance_id:
                    continue  # Skip own events

                await self.process_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in consumer loop: {e}")

    def subscribe(self, listener: callable) -> None:
        """Subscribe to sync events.

        Args:
            listener: Async callback function
        """
        self.sync_listeners.append(listener)
        logger.debug("Sync listener registered")

    def get_instance_info(self) -> Dict[str, Any]:
        """Get information about instances and sync state.

        Returns:
            Sync state information
        """
        return {
            "instance_id": self.instance_id,
            "known_instances": len(self.known_instances),
            "processed_events": len(self.processed_events),
            "queue_size": self.event_queue.qsize(),
            "instances": list(self.known_instances.keys()),
        }


class SyncCoordinator:
    """Coordinate synchronization across all instances."""

    def __init__(self):
        """Initialize coordinator."""
        self.instances: Dict[str, MultiInstanceSync] = {}
        logger.info("Sync coordinator initialized")

    def register_sync_engine(self, instance_id: str, engine: MultiInstanceSync) -> None:
        """Register a sync engine.

        Args:
            instance_id: Instance ID
            engine: MultiInstanceSync instance
        """
        self.instances[instance_id] = engine
        logger.info(f"Sync engine registered: {instance_id}")

    async def broadcast_event(
        self, event_type: SyncEventType, data: Dict[str, Any], source_instance: str
    ) -> int:
        """Broadcast event to all instances.

        Args:
            event_type: Type of event
            data: Event data
            source_instance: Originating instance

        Returns:
            Number of instances notified
        """
        notified = 0

        for instance_id, engine in self.instances.items():
            if instance_id != source_instance:
                try:
                    event = SyncEvent(
                        event_type=event_type,
                        source_instance=source_instance,
                        target_instances=[instance_id],
                        data=data,
                    )
                    await engine.event_queue.put(event)
                    notified += 1
                except Exception as e:
                    logger.error(f"Error notifying {instance_id}: {e}")

        logger.info(f"Event broadcast to {notified} instances")
        return notified

    def get_coordinator_stats(self) -> Dict[str, Any]:
        """Get coordinator statistics.

        Returns:
            Coordinator statistics
        """
        return {
            "total_instances": len(self.instances),
            "instances": [engine.get_instance_info() for engine in self.instances.values()],
        }
