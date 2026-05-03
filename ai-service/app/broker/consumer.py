import json

import aio_pika

from app.broker.publisher import BrokerPublisher, publisher
from app.cache.semantic_cache import semantic_cache
from app.core.config import settings
from app.core.exceptions import BrokerConnectionError
from app.core.logger import logger
from app.rag.vector_store import vector_store
from app.services.processing import process_scan_message
from app.schemas.sarif_schema import ScanResultMessage


class BrokerConsumer:
	def __init__(self, publisher_client: BrokerPublisher | None = None) -> None:
		self._connection: aio_pika.RobustConnection | None = None
		self._channel: aio_pika.RobustChannel | None = None
		self._queue_name = settings.RABBITMQ_CONSUME_QUEUE
		self._publisher = publisher_client or publisher
		self._consumer_tag: str | None = None

	async def start(self) -> None:
		await self._initialize_dependencies()

		try:
			self._connection = await aio_pika.connect_robust(settings.rabbitmq_url)
			self._channel = await self._connection.channel()
			await self._channel.set_qos(prefetch_count=settings.BROKER_PREFETCH)
			queue = await self._channel.declare_queue(self._queue_name, durable=True)
			self._consumer_tag = await queue.consume(self._on_message)
			logger.info(
				"rabbitmq_consumer_started",
				queue=self._queue_name,
				prefetch=settings.BROKER_PREFETCH,
			)
		except Exception as e:
			raise BrokerConnectionError(str(e))

	async def stop(self) -> None:
		if self._channel and not self._channel.is_closed:
			await self._channel.close()
		if self._connection and not self._connection.is_closed:
			await self._connection.close()
		logger.info("rabbitmq_consumer_stopped")

	async def _initialize_dependencies(self) -> None:
		await semantic_cache.connect()
		if not vector_store.is_initialized:
			vector_store.initialize()
		await self._publisher.connect()

	async def _on_message(self, message: aio_pika.IncomingMessage) -> None:
		try:
			payload = json.loads(message.body.decode("utf-8"))
			scan_msg = ScanResultMessage.model_validate(payload)
		except Exception as e:
			logger.error("scan_message_invalid", error=str(e))
			await message.reject(requeue=False)
			return

		try:
			batch = await process_scan_message(scan_msg)
			await self._publisher.publish_batch(batch)
			await message.ack()
		except Exception as e:
			logger.error("scan_processing_failed", scan_id=scan_msg.scan_id, error=str(e))
			await message.nack(requeue=True)

consumer = BrokerConsumer()
