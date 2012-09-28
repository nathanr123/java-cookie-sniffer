import java.util.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;

public class programm
{
	public static void main(String[] args)
	{
		List<PcapIf> devices = new ArrayList<PcapIf>();
		StringBuilder errBuffer = new StringBuilder();
		
		int r = Pcap.findAllDevs(devices, errBuffer);
		if (r == Pcap.NOT_OK || devices.isEmpty())
		{
			System.err.printf("can't collect devices, error" , errBuffer.toString());
			return;
		}
		
		System.out.println("devices found:");
		r = 0;
		for(PcapIf device: devices)
		{
			String descr = (device.getDescription() !=null) ? device.getDescription() : "no description";
			System.out.printf("#%d: %s [%s]\n", r++, device.getName(), descr);
		}
		
		PcapIf device = devices.get(0);
		System.out.printf("Checking Transfer", device.getName());
		
		int snaplen = 64 * 1024;
	    int flags = Pcap.MODE_PROMISCUOUS;
	    int timeout = 10 * 1000;
	    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errBuffer);  
	  
	    if (pcap == null)
	    {
	    	System.err.printf("Error opening device: " + errBuffer.toString());  
	        return;  
	    }  
	        
	    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>()
	    {  
	    	public void nextPacket(PcapPacket packet, String user)
	    	{  
	    		System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",  
	    				new Date(packet.getCaptureHeader().timestampInMillis()),   
	                    packet.getCaptureHeader().caplen(),  // Length actually captured  
	                    packet.getCaptureHeader().wirelen(), // Original length   
	                    user                                 // User supplied object  
	                    );  
	        }  
	    };  
	    
	    PcapBpfProgram program = new PcapBpfProgram();  
	    String expression = "host 192.168.1.1";  
	    int optimize = 0;         // 0 = false  
	    int netmask = 0xFFFFFF00; // 255.255.255.0  
	              
	    if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {  
	      System.err.println(pcap.getErr());  
	      return;  
	    }  
	              
	    if (pcap.setFilter(program) != Pcap.OK) {  
	      System.err.println(pcap.getErr());  
	      return;         
	    }  
	    
	    pcap.loop(10, jpacketHandler, "");   
	    pcap.close();  
	}
}