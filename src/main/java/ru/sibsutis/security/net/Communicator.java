package ru.sibsutis.security.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public interface Communicator {
    void sendMessage(ByteArrayInputStream messageStream, Communicator dst, boolean verbose);
    boolean hasMessageGot();
    ByteArrayOutputStream getMessageStream();
}
