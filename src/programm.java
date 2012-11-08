import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeColumn;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;

public class programm
{
	public static void main(String[] args)
	{
		Display display = new Display();
		Shell shell = new Shell(display);
		shell.setSize(800, 400);
		shell.setText("java-cookie-sniffer");
		
		Tree tree = new Tree(shell, SWT.BORDER);
		tree.setLinesVisible(true);
		tree.setHeaderVisible(true);
		tree.setBounds(137, 10, 637, 342);
		
		TreeColumn trclmnHost = new TreeColumn(tree, SWT.NONE);
		trclmnHost.setWidth(100);
		trclmnHost.setText("Host");
		
		TreeColumn trclmnType = new TreeColumn(tree, SWT.NONE);
		trclmnType.setWidth(100);
		trclmnType.setText("Type");
		
		TreeColumn trclmnContent = new TreeColumn(tree, SWT.NONE);
		trclmnContent.setWidth(433);
		trclmnContent.setText("Content");
		
		Button btnAll = new Button(shell, SWT.RADIO);
		btnAll.setBounds(10, 10, 90, 16);
		btnAll.setText("All");
		
		Combo combo = new Combo(shell, SWT.NONE);
		combo.setEnabled(false);
		combo.setBounds(33, 30, 98, 23);
		
		Button btnSelectHost = new Button(shell, SWT.RADIO);
		btnSelectHost.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
			}
		});
		btnSelectHost.setBounds(10, 32, 90, 16);
		shell.open();
		
		List<PcapIf> devices = new ArrayList<PcapIf>(); //network interfaces
		StringBuilder errBuffer = new StringBuilder(); //errorbuffer
		
		int r = Pcap.findAllDevs(devices, errBuffer); //loading network interface list
		if (r == Pcap.NOT_OK || devices.isEmpty()) //check for device errors
		{
			System.err.printf("can't collect devices, error" , errBuffer.toString()); //print errormesssage
			return;
		}
		
		System.out.println("devices found:"); //device(s) was/were found
		r = 0;
		for(PcapIf device: devices) //retrieving Interface Information
		{
			String descr = (device.getDescription() !=null) ? device.getDescription() : "no description"; //get device description
			System.out.printf("#%d: %s [%s]\n", r++, device.getName(), descr); //print information
		}
		
		PcapIf device = devices.get(0); //set active interface (check for wlan will follow)
		System.out.printf("start sniffing", device.getName()); //starts packet listening
		
		int snaplen = 64 * 1024; //declare 64K packet size
	    int flags = Pcap.MODE_PROMISCUOUS; //declare scan mode to PROMISCUOUS
	    int timeout = 10 * 1000; //declare timeout to 10 sec
	    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errBuffer); //scanner with parameters  
	    
	    if (pcap == null) //check scanner state
	    {
	    	System.err.printf("Error opening device: " + errBuffer.toString()); //print errormessage  
	        return;  
	    }  
	   
	    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() //declare packethandler (string)
	    {  
	    	/* general information
	    	 * 
	    	 * packet structure
	    	 * +-------------------------------------------+
	    	 * | prefix | header | gap | PAYLOAD | postfix |
	    	 * +-------------------------------------------+
	    	 * 
	    	 * typicall header structure
	    	 * +----------------------------+
	    	 * | ethernet | tcp | ip | http |
	    	 * +----------------------------+
	    	 * 
	    	*/
	    	public void nextPacket(PcapPacket packet, String userdefiened) //packet analyzer 
	    	{  	    		
	    		final Tcp tcp = new Tcp(); //tcp-protocoll
	    		final Ip4 ip4 = new Ip4(); //ip-protocoll
	    		final Http http = new Http(); //http-protocoll
	    		
	    		JBuffer tcpPayload = new JBuffer(JMemory.Type.POINTER); //empty tcppayload buffer
	    		int payloadOffset = tcp.getOffset() + tcp.size(); //setting tcp packet payloadoffset
	    		int payloadLength = tcp.getPayloadLength(); //setting tcp packet payloadlenght
	    		
	    		packet.scan(JProtocol.ETHERNET_ID); //scan packet with ethernet protocoll
	    		if (packet.hasHeader(ip4) && packet.hasHeader(tcp) && packet.hasHeader(http)) //check for ip4/tcp/http protocoll
	    		{
	    			tcpPayload.peer(packet, payloadOffset, payloadLength); //loading content to tcpPayload (JBuffer) 
	    		}
	    		
	    		// Standard output:
	    		System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n", //timestamp  
	    				new Date(packet.getCaptureHeader().timestampInMillis()), //latenz(ms)
	                    packet.getCaptureHeader().caplen(), //captured lenght(byte)
	                    packet.getCaptureHeader().wirelen(), //original lenght(byte)
	                    userdefiened); //userdefiened information
	        }  
	    };
	    
	    JBufferHandler<String> jbufferHandler = new JBufferHandler<String>() //declare JBufferhandler (string)
	    {
	    	/* general information
	    	 * 
	    	 * packet structure
	    	 * +-------------------------------------------+
	    	 * | prefix | header | gap | PAYLOAD | postfix |
	    	 * +-------------------------------------------+
	    	 * 
	    	 * typicall header structure
	    	 * +----------------------------+
	    	 * | ethernet | tcp | ip | http |
	    	 * +----------------------------+
	    	 * 
	    	*/
	    	
            PcapHeader header; //empty header
			ByteBuffer buffer; //empty buffer
			Ip4 ip4 = new Ip4(); //ip-protocoll
			Tcp tcp = new Tcp(); //tcp-protocoll
			Http http = new Http(); //http-protocoll
			
	    	public void nextPacket(PcapHeader header, JBuffer buffer, String user) //buffer analyzer
	    	{
				try
				{  
					PcapPacket packet = new PcapPacket(header, buffer); //creating packet  
					packet.scan(JProtocol.ETHERNET_ID); //scan packet with ethernet-protocoll 
	   
					if (packet.hasHeader(ip4) && packet.hasHeader(tcp) && packet.hasHeader(http)) //check for ip4/tcp/http protocoll
					{  
						try
						{
							String bufferText = buffer.toHexdump(); //dump buffer content to temp string
							String clearText = bufferText.replaceAll("[\\dabcdef]{4}:[\\dabcdef ]{0,55}", ""); //replace hex code from string
						    List<String>[] filtered = filterHost("", clearText);
						    PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home") + "\\Desktop\\sniffer.log", true))); //declare stringwriter
						    out.println(bufferText); //logging retreivement
						    out.close(); //release writer
						}
						catch (IOException e) //catching IOException
						{
							System.out.printf("Exception: %s\n", e.getMessage()); //print errormessage
						}
					}
				}
				catch (IllegalArgumentException e) //catching illegal arguments
				{  
					System.out.printf("Exception: %s\n", e.getMessage()); //print errormessage
				}              
	    	}
	    };
	   
	    /* Filter Options (not yet implementet)
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
	    */
	    
	    pcap.loop(0, //count of packets (0 - infinite)
	    		jbufferHandler //buffer handler
	    		//jpacketHandler //packet handler
	    		, ""); //userdefiened information
	    pcap.close(); //release active interface
	}
	
	public static List<String>[] filterHost(String host, String input)
	{
		List<String>[] result = null;
		if (host == "All")
		{
			result = filterContent(input);
		}
		else
		{
		}
	
		return result;
	}
	
	private static List<String>[] filterContent(String input)
	{
		List<String>[] result = null;
		
		return result;
	}
}