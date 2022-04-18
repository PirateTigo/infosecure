package ru.sibsutis.security.net;

import javax.naming.OperationNotSupportedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public class Sender {

    private Communicator client;
    private Communicator server;
    private boolean verbose;
    private boolean needDigest = false;
    private Digester digester;

    public static Builder builder() {
        return new Builder();
    }

    public void send(ByteArrayInputStream message) throws IOException {
        ByteArrayInputStream messageToSend = message;
        if (needDigest) {
            messageToSend = digester.digest(message);
        }
        client.sendMessage(messageToSend, server, verbose);
    }

    public ByteArrayOutputStream getSentMessageStream() throws IOException {
        if (server.hasMessageGot()) {
            ByteArrayOutputStream messageStream = server.getMessageStream();
            if (needDigest) {
                messageStream = digester.verify(messageStream);
            }

            // get message size
            byte[] fullMessage = messageStream.toByteArray();
            ByteBuffer fullMessageBuffer = ByteBuffer.wrap(fullMessage);
            IntBuffer intBuffer = fullMessageBuffer.asIntBuffer();
            int messageSize = intBuffer.get();

            // get message
            byte[] message = new byte[messageSize];
            fullMessageBuffer.position(4);
            fullMessageBuffer.get(message);
            ByteArrayOutputStream sentMessageStream = new ByteArrayOutputStream();
            sentMessageStream.write(message);
            return sentMessageStream;
        } else {
            throw new IllegalStateException("Server hasn't got a message");
        }
    }

    public static class Builder {
        private final Sender sender;

        private Builder() {
            sender = new Sender();
        }

        public Builder setVerbose(boolean verbose) {
            sender.verbose = verbose;
            return this;
        }

        public Builder setNeedDigest(boolean needDigest) {
            sender.needDigest = needDigest;
            return this;
        }

        public Sender build(EntityFactory entityFactory) throws OperationNotSupportedException {
            if (sender.needDigest) {
                sender.digester = entityFactory.createDigester();
            }
            sender.client = entityFactory.createCommunicator();
            sender.server = entityFactory.createCommunicator();
            return sender;
        }
    }

}
