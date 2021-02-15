package il.ac.idc.cs.sinkhole;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

public class UDPServer
{
    private final String ROOT_SERVER_ADDRESS = ".root-servers.net";
    private final int LIMIT_NUMBER_ITERATIONS = 16;
    private final int NUM_OF_ROOT_SERVERS = 13;
    private final int MAX_NUM_OF_SENDING_TRIES = 3;
    private final int DATA_INITIAL_LENGTH = 1024;
    private final int SOCKET_TIMEOUT= 1500;
    private final int portForClient = 5300;
    private final int DNSPort = 53;
    private DatagramSocket clientSocket;
    private DatagramSocket DNSSocket;
    private HashSet<String> blockListDomains;

    public UDPServer(String blockListPath){
        try {
            clientSocket = new DatagramSocket(portForClient);
        } catch (SocketException e) {
            System.err.println("Opening server was failed: " + e.getMessage());
            System.exit(500);
        }

        blockListDomains = readBlockList(blockListPath);
    }

    public void runDNSSinkhole (){
        byte[] dataToReturn;
        int clientPort;
        DatagramPacket responseForClientPacket, clientPacket;
        DNSTableParser clientQuestionTable;
        InetAddress clientIPAddress;

        System.out.println(("Sinkhole server in open and waiting for clients\n"));
        while(true) {
            try {
                //Receive packet from client
                clientPacket = new DatagramPacket(createArrayForData(), DATA_INITIAL_LENGTH);
                clientSocket.receive(clientPacket);

                //Parse client packet to query and save client's port and address
                clientQuestionTable = new DNSTableParser(clientPacket.getData());
                clientIPAddress = clientPacket.getAddress();
                clientPort = clientPacket.getPort();

                //Check if domain is valid to search
                if (blockListDomains != null && blockListDomains.contains(clientQuestionTable.getQuestion())) {
                    dataToReturn = updateErrorFlagsResponse(deleteEmptyBytes(clientPacket.getData()));
                } else {
                    //Open socket for servers and search recursively IP Address for valid domain
                    DNSSocket = new DatagramSocket();
                    responseForClientPacket =
                            searchForIPAddress(deleteEmptyBytes(clientPacket.getData()), InetAddress.getByName(getRandomRootServer()), 0);

                    //Prepare the data before returning back to client
                    dataToReturn = deleteEmptyBytes(updateRAandAAFlags(responseForClientPacket.getData()));
                    DNSSocket.close();
                }

                //Send handled response back to client
                DatagramPacket sendPacket = new DatagramPacket(dataToReturn, dataToReturn.length, clientIPAddress, clientPort);
                clientSocket.send(sendPacket);
                System.out.println(String.format("Request %s was handled\n", clientQuestionTable.getID()));
            }
            catch (Exception e){
                System.err.println("Exception accrued during request : " + e.getMessage());
            }
        }
    }

    private byte[] createArrayForData() {
        byte[] arrayData = new byte[DATA_INITIAL_LENGTH];
        Arrays.fill(arrayData, (byte)-1); //Fill with '-1' for easy erase when needed
        return  arrayData;
    }


    private String getRandomRootServer() {
        Random r = new Random();
        char chosenServer = (char) (r.nextInt(NUM_OF_ROOT_SERVERS) + 'a');
        return  chosenServer + ROOT_SERVER_ADDRESS;
    }
    //Recursively implement the requests and responses with the DNS servers
    private DatagramPacket searchForIPAddress(byte [] packetToSend, InetAddress IpAddress, int count) throws Exception {
        DatagramPacket sendPacket = new DatagramPacket(packetToSend, packetToSend.length, IpAddress, DNSPort);

        //Send packet to server with the timeout
        DNSSocket.send(sendPacket);
        DNSSocket.setSoTimeout(SOCKET_TIMEOUT);

        //Receive server response and parse it
        DatagramPacket receivedPacket = receiveResponse(sendPacket);
        DNSTableParser receivedPacketTable = new DNSTableParser(receivedPacket.getData());

        //Call function recursively while there are no errors with response or response with answer was found
        if (receivedPacketTable.getANCOUNT() == 0 && receivedPacketTable.getNSCOUNT() > 0 && receivedPacketTable.NOERROR() && count < LIMIT_NUMBER_ITERATIONS) {
            return searchForIPAddress(packetToSend, receivedPacketTable.getNextAddress(), count + 1);
        }
        else {
            return receivedPacket;
        }
    }

    private DatagramPacket receiveResponse(DatagramPacket packetToSend) throws Exception {
        int numOfTries = 0;
        while(true) {
            try {
                if(numOfTries == MAX_NUM_OF_SENDING_TRIES) throw new Exception("The server is not responding");
                DatagramPacket receivedPacket = new DatagramPacket(createArrayForData(), DATA_INITIAL_LENGTH);
                DNSSocket.receive(receivedPacket);
                return receivedPacket;
            }
            catch (SocketTimeoutException ex){
                numOfTries++;
                DNSSocket.send(packetToSend);
            }
        }
    }

    //Read and collect the blocklist of domains
    private HashSet<String> readBlockList(String blockListPath) {
        if(blockListPath == null) return null;
        String inValidDomain;
        BufferedReader blockListReader;
        HashSet<String> blockedDomainsSet = new HashSet<String>();
        try {
            blockListReader = new BufferedReader(new FileReader(blockListPath));
            while ((inValidDomain = blockListReader.readLine()) != null) blockedDomainsSet.add(inValidDomain);
            blockListReader.close();
        } catch (Exception e) {
            System.err.println("Failed to read file :" + e);
        }

        return blockedDomainsSet;
    }

    //Set the RA bit and unset the AA bit
    private byte[] updateRAandAAFlags(byte[] data) {
        data[2] = (byte)(data[2] & 0xfb);
        data[3] = (byte)(data[3] | 0x80);
        return data;
    }

    //Set the QR, RD and RA bits, set RCODE=3
    private byte[] updateErrorFlagsResponse(byte[] data) {
        data[2] = (byte)0x81;
        data[3] = (byte)0x83;
        return data;
    }

    private byte[] deleteEmptyBytes(byte[] data){
        int i = data.length - 1;
        while(data[i] == -1) i--;

        return Arrays.copyOfRange(data, 0, i + 1);
    }
}