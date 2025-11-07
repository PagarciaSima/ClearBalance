package com.clear.balance.clearBalance.Utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class SmsUtils {

    @Value("${twilio.from-number}")
    private String fromNumber;

    @Value("${twilio.sid-key}")
    private String sid;

    @Value("${twilio.token-key}")
    private String authToken;

    public void sendSMS(String to, String messageBody) {
        Twilio.init(sid, authToken);

        Message message = Message.creator(
                new PhoneNumber(to),
                new PhoneNumber(fromNumber),
                messageBody
        ).create();

        log.info("SMS sent: {}", message.getSid());
    }
}
