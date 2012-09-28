import java.util.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;

public class reassembler
{
	public static void main(String[] args)
	{
		List<PcapIf> devices = new ArrayList<PcapIf>(); //list of all devices
		StringBuilder errorBuffer = new StringBuilder(); //error messages
		int r = Pcap.findAllDevs(devices, errorBuffer); //setting checksum
		if (r == Pcap.NOT_OK || devices.isEmpty()) //collecting devices
		{
			System.err.printf("error collecting devices %s", errorBuffer.toString());
			return;
		}
		
		System.out.println("devices found:");
		
		r = 0;
		for (PcapIf device: devices) // collecting and|or creating descriptions
		{
			String descr = (device.getDescription() != null) ? device.getDescription()
					: "no description available";
			System.out.printf("#%d: %s [%s]\n", r++, device.getName(), descr);
		}
		
		PcapIf device = devices.get(0);
		System.out.printf("\nChoosing '%s' on your behalf:\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());
		
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 10 * 1000;
		
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);
		
		if (pcap == null)
		{
			System.err.printf("error opening device" + errorBuffer.toString());
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
						user);                               // User supplied object
			}
		};
		
		pcap.loop(10, jpacketHandler, "");
		pcap.close();
	}
}