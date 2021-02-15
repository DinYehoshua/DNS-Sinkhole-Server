package il.ac.idc.cs.sinkhole;

import java.net.InetAddress;
import java.util.Arrays;

public class DNSTableParser {
    private final int QUESTION_LOCATION = 12;
    private final int QUESTION_INITIAL_LENGTH = 512;
    private final int OFFSET_INITIAL_LENGTH = 256;
    private final byte POINTER_CONFIGURATION = (byte) 0xc0;

    private byte[] query;
    private int ID;
    private boolean responseFlag;
    private short responseCode;
    private int answersCount;
    private int authoritiesCount;
    private String questionAddress;
    private int authoritySectionLocation;
    private String responseAnswer;

    public DNSTableParser(byte[] query){
        this.query = query;
        ID = readID();
        responseFlag = readResponseFlag();
        responseCode = readResponseCode();

        //read relevant property to responses only if the response flag is set
        if(responseCode == 0) {
            answersCount = readANCOUNT();
            authoritiesCount = readNSCOUNT();
            questionAddress = readQuestion();
            if (responseFlag) responseAnswer = readResponseAnswer();
        }
    }

    private int readID() { return ((query[0] << 8) & (0x0ff00)) | (query[1] & (0x0ff)); }

    private boolean readResponseFlag() { return (query[2] & 0x080) > 0; }

    private short readResponseCode() { return (short)(query[3] & 0x0f); }

    private int readANCOUNT() { return ((query[6] << 8) | query[7]) & 0x0ffff; }

    private int readNSCOUNT() { return ((query[8] << 8) | query[9]) & 0x0ffff; }

    //Read query question by using readAddress method to read bytes
    private String readQuestion() { return readAddress(QUESTION_LOCATION, QUESTION_INITIAL_LENGTH); }

    //The method checks if the response got at least one answer:
    // If there is, it read the answer IP address
    // If not, it read the first server that appears in the authority section
    private String readResponseAnswer() {
        int addressSizeLocation = getAddressSizeLocation();
        int addressSize = getAnswerAddressSize(addressSizeLocation);
        int nextServerAddressLocation = addressSizeLocation + 2;
        
        if (answersCount == 0){
            return readAddress(nextServerAddressLocation, addressSize);
        } else {
            return null;
        }
    }

    private int getAddressSizeLocation() {
        int byteToRead = authoritySectionLocation;
        while (query[byteToRead] != 0) byteToRead++;

        //Check if the name of the answer use pointers
        if(byteToRead - authoritySectionLocation > 2) return byteToRead + 9;
        return byteToRead + 8;
    }

    private int getAnswerAddressSize(int addressSizeLocation) {
        return ((this.query[addressSizeLocation] << 8) | this.query[addressSizeLocation + 1]) & 0x0ffff;
    }

    // Casts address from the query into string
    //The method works Recursively when we have pointers
    private String readAddress(int byteToRead, int addressSize) {
        int index;
        byte[] addressBytes = new byte[addressSize];
        StringBuilder address = new StringBuilder();

        while (query[byteToRead] != 0 && query[byteToRead] != POINTER_CONFIGURATION) {
            index = 0;
            for (int i = 1; i <= query[byteToRead]; i++) {
                addressBytes[index] = query[i + byteToRead];
                index++;
            }

            address.append(new String(Arrays.copyOfRange(addressBytes, 0, index)));
            byteToRead += 1 + query[byteToRead];
            if (query[byteToRead] != 0) address.append(".");
        }

        if (query[byteToRead] == POINTER_CONFIGURATION) address.append(readAddress(query[byteToRead + 1], OFFSET_INITIAL_LENGTH));
        if(addressSize == QUESTION_INITIAL_LENGTH) authoritySectionLocation = byteToRead + 5;

        return address.toString();
    }

    public int getID() { return ID; }

    public boolean NOERROR() { return responseCode == 0; }

    public int getANCOUNT(){ return answersCount; }

    public int getNSCOUNT(){ return authoritiesCount; }

    public String getQuestion() { return questionAddress; }

    public String getResponseAnswer() { return responseAnswer; }

    public InetAddress getNextAddress() throws Exception { return  InetAddress.getByName(getResponseAnswer()); }
}