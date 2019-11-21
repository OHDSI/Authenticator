package org.ohdsi.authenticator.service.proxy;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

/**
 This is a really simple implementation of Http Proxy.
 Basically what is happening is
 - the client sends an HTTPS request to proxy it comes with CONNECT keyword.
 - The Proxy sends HTTP/1.1 200 OK to the client after establishing a connection with the upstream server.
 - The proxy is supplying the client's incoming input stream to the upstream server and incoming stream from the upstream server to the client.
 */
@Slf4j
public class TestHttpProxy {

    public static final String APP_NAME = "SimpleProxy/0.1";
    public static final int HTTP_PROXY_PORT = 9990;
    public static final Pattern CONNECT_PATTERN = Pattern.compile("CONNECT (.+):(.+) HTTP/(1\\.[01])", Pattern.CASE_INSENSITIVE);

    public void start() {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(HTTP_PROXY_PORT)) {
                Socket socket;
                while ((socket = serverSocket.accept()) != null) {
                    handleRequest(socket);
                }
            } catch (IOException e) {
                log.error("Inner exception", e);
            }
        }).start();
    }

    public void handleRequest(Socket socket) {

        RequestHandler requestHandler = new RequestHandler(socket);
        requestHandler.start();
    }

    public static class RequestHandler extends Thread {

        private Socket clientSocket;

        public RequestHandler(Socket clientSocket) {

            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {

            try (Scanner scanner = new Scanner(clientSocket.getInputStream());
                 OutputStreamWriter outputStreamWriter = new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.ISO_8859_1)
            ) {
                if (!scanner.hasNextLine()) {
                    outputStreamWriter.write("HTTP/1.1 400 Empty request. \r\n Proxy-agent: " + APP_NAME + "\n\n \r\n");
                    outputStreamWriter.flush();
                    return;
                }

                String firstHeader = scanner.nextLine();
                Matcher matcher = CONNECT_PATTERN.matcher(firstHeader);

                if (matcher.matches()) {
                    String forwardHost = matcher.group(1);
                    String forwardPort = matcher.group(2);
                    String httpVersion = matcher.group(3);

                    try (Socket forwardSocket = new Socket(forwardHost, Integer.parseInt(forwardPort))) {

                        outputStreamWriter.write("HTTP/" + httpVersion + " 200 Connection established\r\n Proxy-agent: " + APP_NAME + "\n\n \r\n");
                        outputStreamWriter.flush();

                        Executors.newFixedThreadPool(2).invokeAll(Arrays.asList(
                                () -> forwardData(forwardSocket, clientSocket),
                                () -> forwardData(clientSocket, forwardSocket)
                        ));

                    } catch (IOException | NumberFormatException e) {
                        outputStreamWriter.write("HTTP/" + httpVersion + " 502 Bad Gateway\r\n Proxy-agent: " + APP_NAME + "\r\n \r\n");
                        outputStreamWriter.flush();
                    } catch (InterruptedException e) {
                        log.error("Inner exception", e);
                        outputStreamWriter.write("HTTP/1.1 500 Inner error. \r\n Proxy-agent: " + APP_NAME + "\n\n \r\n");
                        outputStreamWriter.flush();
                    }
                }
            } catch (IOException e) {
                log.error("Inner exception", e);
            }
        }

        private boolean forwardData(Socket inputSocket, Socket outputSocket) {

            try {
                IOUtils.copy(inputSocket.getInputStream(), outputSocket.getOutputStream());
                return true;
            } catch (IOException e) {
                log.error("Cannot forward data", e);
            }
            return false;

        }
    }
}