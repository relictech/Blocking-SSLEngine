import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class SSLPeer {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(1);

    private static final int MAX_PKT_SZ = 129_000;
    private static final ThreadLocal<ByteBuffer> EMPTY_BUFFER_TL = ThreadLocal.withInitial(() -> ByteBuffer.allocate(MAX_PKT_SZ));

    private final InputStream is;
    private final OutputStream os;
    private final SSLEngine ssl;

    private byte[] leftOver = null;

    public SSLPeer(InputStream is, OutputStream os, SSLEngine ssl) {
        this.is = is;
        this.os = os;
        this.ssl = ssl;
    }

    public byte[] read() throws IOException {
        ByteBuffer outNetBB = EMPTY_BUFFER_TL.get();
        outNetBB.clear();
        byte[] inNetBuf = new byte[MAX_PKT_SZ];
        int offset = 0;
        if (leftOver != null) {
            System.arraycopy(leftOver, 0, inNetBuf, 0, leftOver.length);
            offset += leftOver.length;
            leftOver = null;
        }
        boolean needRead = offset == 0;
        while (true) {
            if (needRead) {
                int read = is.read(inNetBuf, offset, inNetBuf.length - offset);
                if (read == -1) {
                    throw new IOException("End of stream reached during handshake");
                }
                offset += read;
            }
            ByteBuffer inNetBB = ByteBuffer.wrap(inNetBuf, 0, offset);
            SSLEngineResult res = ssl.unwrap(inNetBB, outNetBB);
            if (res.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                if (res.bytesConsumed() != 0) {
                    throw new IOException("SSL unwrap error - UNDERFLOW consumed bytes: " + res.bytesConsumed());
                }
                needRead = true;
                continue;
            }
            if (res.getStatus() == SSLEngineResult.Status.CLOSED) {
                return null;
            }
            if (res.bytesConsumed() != offset) {
                int left = offset - res.bytesConsumed();
                leftOver = new byte[left];
                System.arraycopy(inNetBuf, res.bytesConsumed(), leftOver, 0, left);
            }
            if (res.bytesProduced() == 0) {
                if (res.bytesConsumed() == 0) {
                    throw new IOException("SSL unwrap error - no progress");
                }
                return read();
            }

            byte[] appData = new byte[res.bytesProduced()];
            System.arraycopy(outNetBB.array(), 0, appData, 0, appData.length);
            return appData;
        }
    }

    public void write(byte[] data) throws IOException {
        ByteBuffer outNetBB = EMPTY_BUFFER_TL.get();
        ByteBuffer appBB = ByteBuffer.wrap(data);
        while (true) {
            outNetBB.clear();
            SSLEngineResult res = ssl.wrap(appBB, outNetBB);
            if (res.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new IOException("SSL wrap error - attempt to write to closed SSLEngine");
            }
            byte[] outNetBuf = new byte[res.bytesProduced()];
            System.arraycopy(outNetBB.array(), 0, outNetBuf, 0, outNetBuf.length);
            os.write(outNetBuf);
            if (!appBB.hasRemaining()) {
                os.flush();
                return;
            }
        }
    }

    public void close() throws IOException {
        ssl.closeOutbound();
        ByteBuffer outNetBB = EMPTY_BUFFER_TL.get();
        while (!ssl.isOutboundDone()) {
            outNetBB.clear();
            SSLEngineResult res = ssl.wrap(EMPTY_BUFFER, outNetBB);
            if (res.bytesProduced() == 0) {
                break;
            }
            if (res.bytesConsumed() != 0) {
                throw new IOException("SSL close error - close wrap consumed bytes: " + res.bytesConsumed());
            }
            byte[] outNetBuf = new byte[res.bytesProduced()];
            System.arraycopy(outNetBB.array(), 0, outNetBuf, 0, outNetBuf.length);
            os.write(outNetBuf);
        }
        os.flush();
    }

    public void handshake() throws IOException {
        try {
            ssl.beginHandshake();
            SSLEngineResult.HandshakeStatus stat;
            w:
            while (true) {
                stat = ssl.getHandshakeStatus();
                switch (stat) {
                    case NEED_UNWRAP: {
                        byte[] inNetBuf = new byte[MAX_PKT_SZ];
                        int offset = 0;
                        if (leftOver != null) {
                            System.arraycopy(leftOver, 0, inNetBuf, 0, leftOver.length);
                            offset += leftOver.length;
                            leftOver = null;
                        }
                        boolean needRead = offset == 0;
                        while (true) {
                            if (needRead) {
                                int read = is.read(inNetBuf, offset, inNetBuf.length - offset);
                                if (read == -1) {
                                    throw new IOException("SSL handshake unwrap error - end of stream reached");
                                }
                                offset += read;
                            }
                            ByteBuffer inNetBB = ByteBuffer.wrap(inNetBuf, 0, offset);
                            SSLEngineResult res = ssl.unwrap(inNetBB, EMPTY_BUFFER);
                            if (res.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                                needRead = true;
                                continue;
                            }
                            if (res.bytesProduced() != 0) {
                                throw new IOException("SSL handshake unwrap error - produced application data");
                            }
                            if (res.getStatus() == SSLEngineResult.Status.CLOSED) {
                                throw new IOException("SSL handshake unwrap error - SSLEngine closed");
                            }
                            if (res.bytesConsumed() != offset) {
                                int left = offset - res.bytesConsumed();
                                leftOver = new byte[left];
                                System.arraycopy(inNetBuf, res.bytesConsumed(), leftOver, 0, left);
                            }
                            break;
                        }
                        break;
                    }
                    case NEED_WRAP: {
                        ByteBuffer outNetBB = EMPTY_BUFFER_TL.get();
                        outNetBB.clear();
                        SSLEngineResult res = ssl.wrap(EMPTY_BUFFER, outNetBB);
                        if (res.getStatus() != SSLEngineResult.Status.OK) {
                            // Initial warp should always be OK, no need to handle BUFFER_OVERFLOW
                            throw new IOException("SSL handshake wrap error - NOT OK status: " + res.getStatus());
                        }
                        if (res.bytesConsumed() != 0) {
                            throw new IOException("SSL handshake wrap error - wrap consumed bytes: " + res.bytesConsumed());
                        }
                        byte[] outNetBuf = new byte[res.bytesProduced()];
                        System.arraycopy(outNetBB.array(), 0, outNetBuf, 0, outNetBuf.length);
                        os.write(outNetBuf);
                        os.flush();
                        break;
                    }
                    case NEED_TASK: {
                        Runnable task;
                        while ((task = ssl.getDelegatedTask()) != null) {
                            task.run();
                        }
                        break;
                    }
                    default:
                        break w;
                }
            }
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }
}
