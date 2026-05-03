package com.example.aicybersecuritycopilot.broker.config;

import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    public static final String SCAN_RESULTS_QUEUE = "scan.results";

    @Bean
    public Queue scanResultsQueue() {
        return new Queue(SCAN_RESULTS_QUEUE, true); // durable = true
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }
}
