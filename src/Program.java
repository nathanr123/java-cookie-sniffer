import java.lang.reflect.Field;
import java.net.SocketException;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeColumn;
import org.eclipse.swt.widgets.TreeItem;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Program
{
	static Boolean close;
	static Boolean cookies;
	static Boolean mails;
	static Tree tree;
	static TreeItem[] items;
	static PcapPacket[] packets;
	
	public static void main(String[] args) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, SocketException
	{
		//Initialize variables
		close = false;
		items = new TreeItem[] {};
		packets = new PcapPacket[] {};
		// Determinate OS and architecture and load specific library
		Map<String, String> env = System.getenv(); // Load environment strings
		String arch = System.getProperty("os.arch"); // Check Architecture
		String os = System.getProperty("os.name");  // Check OS
		String libPath = System.getProperty("java.library.path"); // save old libraryPath

		/* >>> General Information <<<
		 * Reinitialize java.lib.path
		 * 
		 * System.setProperty( "java.library.path", env.get("OS + Architecture") + libPath );	<< set new library Path
		 * Field fieldSysPath = ClassLoader.class.getDeclaredField( "sys_paths" );				<< set Field ('sys_paths')
		 *  
		 * fieldSysPath.setAccessible( true );													<< set access
		 * fieldSysPath.set( null, null );														<< set to null
		 * System.load(env.get("OS + Architecture"));											<< executing load starts a static method for reinitializing the java.lib.path
		 * */
		
		// Windows OS library load
		if (os.toLowerCase().contains("windows")) {
			if (arch.contains("64")) {
				try {
					System.setProperty( "java.library.path", env.get("win64") + libPath );
					 
					Field fieldSysPath = ClassLoader.class.getDeclaredField( "sys_paths" );
					fieldSysPath.setAccessible( true );
					fieldSysPath.set( null, null );
					System.load(env.get("win64"));
				}
				catch (UnsatisfiedLinkError e) {
					System.out.print(e.getMessage());
				}
			}
			else {
				try {
				System.setProperty( "java.library.path", env.get("win86") + libPath );
				 
				Field fieldSysPath = ClassLoader.class.getDeclaredField( "sys_paths" );
				fieldSysPath.setAccessible( true );
				fieldSysPath.set( null, null );
				System.load(env.get("win86"));
				}
				catch (UnsatisfiedLinkError e) {
					System.out.print(e.getMessage());
				}
			}
		}
		
		// Linux OS library load
		else {
			if (arch.contains("64"))
				try {
				System.setProperty( "java.library.path", env.get("linux64") + libPath );
			 
				Field fieldSysPath = ClassLoader.class.getDeclaredField( "sys_paths" );
				fieldSysPath.setAccessible( true );
				fieldSysPath.set( null, null );
				System.load(env.get("linux64"));
				}
				catch (UnsatisfiedLinkError e) {
					System.out.print(e.getMessage());
				}
			else {
				try {
				System.setProperty( "java.library.path", env.get("linux86") + libPath );
			 
				Field fieldSysPath = ClassLoader.class.getDeclaredField( "sys_paths" );
				fieldSysPath.setAccessible( true );
				fieldSysPath.set( null, null );
				System.load(env.get("linux86"));
				}
				catch (UnsatisfiedLinkError e) {
					System.out.print(e.getMessage());
				}
			}
		}
		
		//Starting Sniffer
		new Sniffer().start();

		// Starting GUI
		Display display = new Display();
		Shell shell = new Shell(display);
		shell.setSize(800, 400);
		shell.setText("java-cookie-sniffer");
		
		tree = new Tree(shell, SWT.BORDER);
		tree.setLinesVisible(true);
		tree.setHeaderVisible(true);
		tree.setBounds(137, 45, 637, 307);
		
		TreeColumn trclmnHost = new TreeColumn(tree, SWT.NONE);
		trclmnHost.setWidth(100);
		trclmnHost.setText("Source");
		
		TreeColumn trclmnDestination = new TreeColumn(tree, SWT.NONE);
		trclmnDestination.setWidth(100);
		trclmnDestination.setText("Destination");
		
		TreeColumn trclmnType = new TreeColumn(tree, SWT.NONE);
		trclmnType.setWidth(100);
		trclmnType.setText("Type");
		
		TreeColumn trclmnContent = new TreeColumn(tree, SWT.NONE);
		trclmnContent.setWidth(433);
		trclmnContent.setText("Content");
		
		final Button btnCookies = new Button(shell, SWT.CHECK);
		btnCookies.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				cookies = btnCookies.getSelection();
				updateTree();
			}
		});
		btnCookies.setBounds(10, 10, 93, 16);
		btnCookies.setText("Cookies");
		
		final Button btnMails = new Button(shell, SWT.CHECK);
		btnMails.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				mails = btnMails.getSelection();
				updateTree();
			}
		});
		btnMails.setBounds(109, 10, 93, 16);
		btnMails.setText("Mails");
		
		List list = new List(shell, SWT.BORDER);
		list.setBounds(10, 45, 121, 307);
		shell.open();
		
		//Interfaces.collectDevices();
		
		//while (!close) {
		//}
		
		Timer timer = new Timer();
		TimerTask task = new TimerTask()
		{
			public void run()
			{
				/*Ethernet ethernet = new Ethernet();
				Tcp tcp = new Tcp();
				Ip4 ip4 = new Ip4();
				
				for (int i = 0; i < packets.length; i++)
				{
					items = (TreeItem[])resizeTreeItemArray(items, items.length + 1);
					items[items.length] = new TreeItem(tree, tree.getItemCount());
					items[items.length].setData("Source", packets[i].getHeader(tcp).source());
					items[items.length].setData("Destination", packets[i].getHeader(tcp).destination());
					items[items.length].setData("Type", "");
					items[items.length].setData("Content", "");
				}*/
			}
		};
		
		timer.scheduleAtFixedRate(task, 0, 1000);
	}	
	
	protected static void updateTree()
	{
		if(!cookies)
		{
		}
		else if(!mails)
		{
		}
	}

	public static void addPacket(PcapPacket packet)//String source, String destination, String content)
	{
		try
		{
			packets = (PcapPacket[])resizePcapArray(packets, packets.length + 1);
			packets[packets.length - 1] = packet; 
		}
		catch (Exception e) {
			System.out.print(e.getMessage());
		}
	}
	
	public static PcapPacket[] resizePcapArray(PcapPacket[] array, int length) 
	{
		PcapPacket[] temp = new PcapPacket[length];
		for (int i = 0; i < array.length; i++)
		{
			temp[i] = array[i];
		}
		return temp;
	}
	
	public static TreeItem[] resizeTreeItemArray(TreeItem[] items, int length)
	{
		TreeItem[] temp = new TreeItem[length];
		for (int i = 0; i < items.length; i++)
		{
			temp[i] = items[i];
		}
		return temp;
	}
}