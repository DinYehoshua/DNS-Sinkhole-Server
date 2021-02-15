package il.ac.idc.cs.sinkhole;

public class SinkholeServer {
    public static void main (String[] args)  {
        String path = null;
        if(args.length != 0) path = args[0];

        UDPServer udpServer = new UDPServer(path);
        udpServer.runDNSSinkhole();
    }
}