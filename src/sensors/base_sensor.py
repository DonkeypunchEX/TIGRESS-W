"""Abstract sensor base class with a bounded reading buffer."""

from abc import ABC, abstractmethod
from typing import Callable, List


class BaseSensor(ABC):
    """Base for all sensors: manages the reading buffer and subscribers."""

    #: Maximum number of recent readings kept in memory per sensor.
    DEFAULT_BUFFER_LIMIT = 1000

    def __init__(self, sensor_id: str, sensor_type: str, config: dict):
        self.sensor_id = sensor_id
        self.sensor_type = sensor_type
        self.config = config
        self.recording = False
        self.connected = False
        self.data_buffer: List[dict] = []
        self._buffer_limit = int(config.get("buffer_limit", self.DEFAULT_BUFFER_LIMIT))
        self._subscribers: List[Callable] = []

    @abstractmethod
    def connect(self) -> bool:
        """Connect to the underlying sensor; return True on success."""

    @abstractmethod
    def disconnect(self):
        """Stop recording and release the sensor."""

    @abstractmethod
    def start_recording(self) -> bool:
        """Start the background sampling loop; return True on success."""

    @abstractmethod
    def stop_recording(self):
        """Stop the background sampling loop."""

    def subscribe(self, callback: Callable):
        """Register a callback invoked with each new reading."""
        self._subscribers.append(callback)

    def record(self, data: dict):
        """Append a reading to the bounded buffer and notify subscribers."""
        self.data_buffer.append(data)
        overflow = len(self.data_buffer) - self._buffer_limit
        if overflow > 0:
            del self.data_buffer[:overflow]
        self.notify(data)

    def notify(self, data: dict):
        """Deliver a reading to every subscriber, ignoring their errors."""
        for cb in self._subscribers:
            try:
                cb(data)
            except Exception:
                pass

    def get_buffer(self) -> List[dict]:
        """Return the current in-memory buffer of recent readings."""
        return self.data_buffer

    def get_status(self) -> dict:
        """Return a status snapshot (id, type, state, buffer size)."""
        return {
            "id": self.sensor_id,
            "type": self.sensor_type,
            "recording": self.recording,
            "connected": self.connected,
            "buffer_size": len(self.data_buffer),
        }
