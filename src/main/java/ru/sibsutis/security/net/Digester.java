package ru.sibsutis.security.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public interface Digester {
    ByteArrayInputStream digest(ByteArrayInputStream messageStream) throws IOException;
    ByteArrayOutputStream verify(ByteArrayOutputStream messageStream) throws IOException;
}
