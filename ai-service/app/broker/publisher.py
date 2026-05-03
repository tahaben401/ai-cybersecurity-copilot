import json

import aio_pika
from aio_pika import DeliveryMode, Message

from app.core.config import settings
from app.core.exceptions import BrokerConnectionError
from app.core.logger import logger
from app.schemas.patch_schema import AIBatchResult


class BrokerPublisher:
	def __init__(self) -> None:
		self._connection: aio_pika.RobustConnection | None = None
		self._channel: aio_pika.RobustChannel | None = None
		self._queue_name = settings.RABBITMQ_PUBLISH_QUEUE

	async def connect(self) -> None:
		if self._connection and not self._connection.is_closed:
			return
		try:
			self._connection = await aio_pika.connect_robust(settings.rabbitmq_url)
			self._channel = await self._connection.channel()
			await self._channel.declare_queue(self._queue_name, durable=True)
			logger.info("rabbitmq_publisher_connected", queue=self._queue_name)
		except Exception as e:
			raise BrokerConnectionError(str(e))

	async def publish_batch(self, batch: AIBatchResult) -> None:
		if not self._channel or self._channel.is_closed:
			await self.connect()

		payload = batch.model_dump()
		body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

		message = Message(
			body,
			content_type="application/json",
			delivery_mode=DeliveryMode.PERSISTENT,
			correlation_id=batch.scan_id,
			message_id=f"{batch.scan_id}:{batch.project_id}",
		)

		try:
			await self._channel.default_exchange.publish(
				message,
				routing_key=self._queue_name,
			)
			logger.info(
				"rabbitmq_batch_published",
				scan_id=batch.scan_id,
				results=len(batch.results),
			)
		except Exception as e:
			raise BrokerConnectionError(str(e))

	async def close(self) -> None:
		if self._channel and not self._channel.is_closed:
			await self._channel.close()
		if self._connection and not self._connection.is_closed:
			await self._connection.close()
		logger.info("rabbitmq_publisher_closed")


publisher = BrokerPublisher()
