package com.example.aicybersecuritycopilot.broker.service;

import com.example.aicybersecuritycopilot.broker.config.RabbitMQConfig;
import com.example.aicybersecuritycopilot.broker.dto.ScanResultMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanResultPublisher {

    private final RabbitTemplate rabbitTemplate;

    @Async
    public void publishScanResults(ScanResultMessage message) {
        log.info("Publishing scan results to RabbitMQ for scanId: {}", message.getScanId());
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.SCAN_RESULTS_QUEUE, message);
            log.info("Successfully published scan results to RabbitMQ.");
        } catch (Exception e) {
            log.error("Failed to publish scan results to RabbitMQ: {}", e.getMessage(), e);
        }
    }
}
