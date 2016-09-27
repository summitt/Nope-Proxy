package josh.ui;




import javax.swing.JPanel;

import javax.swing.border.LineBorder;
import java.awt.Color;


import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.Font;
import java.awt.Frame;

import javax.swing.JCheckBox;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Queue;
import java.util.Timer;
import java.util.Vector;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;

import org.bouncycastle.util.encoders.Hex;
import org.hibernate.Session;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import josh.dao.HibHelper;
import josh.dao.UpdateDBTask;
import josh.nonHttp.GenericMiTMServer;
import josh.nonHttp.PythonMangler;
import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.nonHttp.utils.ColoredTableCellRenderer;
import josh.nonHttp.utils.LogEntry;
import josh.nonHttp.utils.NonHTTPTableModel;
import josh.nonHttp.utils.Table;
import josh.utils.SharedBoolean;
import josh.utils.events.DNSConfigListener;
import josh.utils.events.DNSEvent;
import josh.utils.events.DNSTableEvent;
import josh.utils.events.DNSTableEventListener;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollPane;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JSplitPane;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import javax.swing.JRadioButton;
import java.awt.GridLayout;
import javax.swing.UIManager;
import javax.swing.border.TitledBorder;
import javax.swing.border.EtchedBorder;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.ButtonGroup;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.SystemColor;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FileDialog;
import javax.swing.ListSelectionModel;
import java.awt.FlowLayout;
import javax.swing.JEditorPane;


@SuppressWarnings("serial")
public class NonHttpUI extends JPanel implements ProxyEventListener, DNSTableEventListener, PythonOutputEventListener{

	public IBurpExtenderCallbacks Callbacks;
	public IExtensionHelpers Helpers;
	private final JButton btnStartDns;
	private boolean AUTOSTART = false;
	public boolean isDNSRunning = false;
	public boolean isLearning = false;
	public String DNSIP = "";
	private int IFNUM;
	JLabel lblCurrentIpAddress = new JLabel("Current Ip Address: ");
	JCheckBox isSSL;
	public DefaultTableModel tbm;
	private HashMap<Integer,GenericMiTMServer> threads = new HashMap<Integer,GenericMiTMServer>();
	public NonHTTPTableModel ntbm;
	private JTabbedPane BurpTabs;
	private NonHTTPTableModel intbm;
	private JButton btnIntercept;
	JRadioButton isBoth;
	JRadioButton isC2S;
	JRadioButton isS2C;
	Boolean EnableTCPDump=true;
	private JTable DnsListTable;
	public DefaultTableModel dnstTbm;
	private JLabel errorMsg;
	public int DNSPort;
	private Table logTable;
	private JTextField IfTxtBox;
	private JTextField dnsIpTxt;
	private JTextField SvrAddr;
	private JTextField LstnPort;
	private JTextField SvrPort;
	private JTextField certName;
	private JTable ListTable;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JTextField interceptInfo;
	private JTextArea txtRules;
	private JTextField txtDNSPort;
	private JLabel lblSelected;
	private Queue<LogEntry> queue = new LinkedList<LogEntry>();
	private Timer timer;
	private JEditorPane PythonConsole;
	
	public boolean useDefault= false;
	

	//GenericMiTMServer mtm;


	/**
	 * Create the frame.
	 */
	public NonHttpUI(IBurpExtenderCallbacks Callbacks, IExtensionHelpers Helpers, SharedBoolean sb) {
		setLayout(new GridLayout(0, 1, 0, 0));
		this.Callbacks = Callbacks;
		this.Helpers = Helpers;
		
		//#####################################################################################
		// Setup Saved Configs
		AUTOSTART = Boolean.parseBoolean(this.getProperties("autoStart", "false"));
		IFNUM = Integer.parseInt(this.getProperties("interface","0"));
		
		//#####################################################################################
		// Create the 3 tabs 
		BurpTabs = new JTabbedPane();
		JPanel Intercept = new JPanel();
		JScrollPane History = new JScrollPane(); 
		JPanel Options = new JPanel();
		this.setBorder(null);
		GridBagLayout gbl_Options = new GridBagLayout();
		gbl_Options.columnWidths = new int[]{1067, 0};
		gbl_Options.rowHeights = new int[]{423, 220, 0};
		gbl_Options.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_Options.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		Options.setLayout(gbl_Options);
		String local="---";
		String tmpPort = this.getProperties("dnsport");
		if(tmpPort == null || tmpPort.equals(""))
			tmpPort="5353";
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "DNS Settings", TitledBorder.LEADING, TitledBorder.TOP, null, UIManager.getColor("CheckBoxMenuItem.selectionBackground")));
		GridBagConstraints gbc_panel_2 = new GridBagConstraints();
		gbc_panel_2.fill = GridBagConstraints.BOTH;
		gbc_panel_2.insets = new Insets(0, 0, 5, 0);
		gbc_panel_2.gridx = 0;
		gbc_panel_2.gridy = 0;
		Options.add(panel_2, gbc_panel_2);
		GridBagLayout gbl_panel_2 = new GridBagLayout();
		gbl_panel_2.columnWidths = new int[]{42, 290, 242, 0, 0};
		gbl_panel_2.rowHeights = new int[]{110, 27, 0, 223, 0};
		gbl_panel_2.columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_panel_2.rowWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		panel_2.setLayout(gbl_panel_2);
																
		//#####################################################################################
	    // DNS Controls for  Options tab
		JPanel panel = new JPanel();
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.insets = new Insets(0, 0, 5, 5);
		gbc_panel.gridwidth = 2;
		gbc_panel.gridx = 1;
		gbc_panel.gridy = 0;
		panel_2.add(panel, gbc_panel);
		panel.setBorder(null);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{61, 44, 73, 130, 0};
		gbl_panel.rowHeights = new int[]{30, 33, 23, 0};
		gbl_panel.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		btnStartDns = new JButton("Start DNS");
		btnStartDns.setBackground(Color.RED);
		btnStartDns.setToolTipText("DNS will respond to all requests with the IP address in Blue below.");
		btnStartDns.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ToggleDNS( dnsIpTxt.getText() ,Integer.parseInt(txtDNSPort.getText()));
				if(isDNSRunning){


				}else{
					btnStartDns.setBackground(Color.GREEN);
					btnStartDns.setText("Stop DNS");
					isDNSRunning = true;
					//lblStatusDNS.setText("DNS ON");
				}

			}
		});
		GridBagConstraints gbc_btnStartDns = new GridBagConstraints();
		gbc_btnStartDns.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnStartDns.insets = new Insets(0, 0, 5, 5);
		gbc_btnStartDns.gridwidth = 2;
		gbc_btnStartDns.gridx = 0;
		gbc_btnStartDns.gridy = 0;
		panel.add(btnStartDns, gbc_btnStartDns);
		JLabel lblDnsIp = new JLabel("DNS Response Ip:");
		GridBagConstraints gbc_lblDnsIp = new GridBagConstraints();
		gbc_lblDnsIp.anchor = GridBagConstraints.EAST;
		gbc_lblDnsIp.insets = new Insets(0, 0, 5, 5);
		gbc_lblDnsIp.gridx = 2;
		gbc_lblDnsIp.gridy = 0;
		panel.add(lblDnsIp, gbc_lblDnsIp);
		
		//#####################################################################################
	    // Network Interfaces Information for  Options tab
		IfTxtBox = new JTextField();
		IfTxtBox.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent evt) {
				if(IfTxtBox.getText().matches("^[0-9]$")){
					updateInterface(IfTxtBox.getText());
					updateInterfaceInformation();	
				}
			}
		});
				

		dnsIpTxt = new JTextField();
		dnsIpTxt.setToolTipText("Must restart the DNS server when the DNS IP is changed.");
		dnsIpTxt.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				if(dnsIpTxt.getText().matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")){
					DNSIP = dnsIpTxt.getText();
					Callbacks.printOutput("DNSIP Changed to : " +  DNSIP);
				}
			}
		});
		GridBagConstraints gbc_dnsIpTxt = new GridBagConstraints();
		gbc_dnsIpTxt.anchor = GridBagConstraints.NORTH;
		gbc_dnsIpTxt.fill = GridBagConstraints.HORIZONTAL;
		gbc_dnsIpTxt.insets = new Insets(0, 0, 5, 0);
		gbc_dnsIpTxt.gridx = 3;
		gbc_dnsIpTxt.gridy = 0;
		panel.add(dnsIpTxt, gbc_dnsIpTxt);
		dnsIpTxt.setColumns(10);
		dnsIpTxt.setText(local);
		DNSIP = dnsIpTxt.getText();
		
				JLabel lblInterface = new JLabel("Interface:");
				GridBagConstraints gbc_lblInterface = new GridBagConstraints();
				gbc_lblInterface.fill = GridBagConstraints.HORIZONTAL;
				gbc_lblInterface.insets = new Insets(0, 0, 5, 5);
				gbc_lblInterface.gridx = 0;
				gbc_lblInterface.gridy = 1;
				panel.add(lblInterface, gbc_lblInterface);


		IfTxtBox.setToolTipText("The interface number from the list below.");
		IfTxtBox.setText(""+IFNUM);
		GridBagConstraints gbc_IfTxtBox = new GridBagConstraints();
		gbc_IfTxtBox.anchor = GridBagConstraints.SOUTH;
		gbc_IfTxtBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_IfTxtBox.insets = new Insets(0, 0, 5, 5);
		gbc_IfTxtBox.gridx = 1;
		gbc_IfTxtBox.gridy = 1;
		panel.add(IfTxtBox, gbc_IfTxtBox);
		IfTxtBox.setColumns(10);
		
		JLabel lblDnsport = new JLabel("DNS Listener Port:");
		GridBagConstraints gbc_lblDnsport = new GridBagConstraints();
		gbc_lblDnsport.anchor = GridBagConstraints.EAST;
		gbc_lblDnsport.insets = new Insets(0, 0, 5, 5);
		gbc_lblDnsport.gridx = 2;
		gbc_lblDnsport.gridy = 1;
		panel.add(lblDnsport, gbc_lblDnsport);
		
		final JCheckBox chckbxStartDnsOn = new JCheckBox("Start DNS on Start Up");
		chckbxStartDnsOn.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent arg0) {
				updateAutoStart(chckbxStartDnsOn.isSelected());
			}
		});
		
		txtDNSPort = new JTextField();
		txtDNSPort.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				DNSPort = Integer.parseInt(txtDNSPort.getText());
				updateProperties("dnsport", ""+DNSPort);
			}
		});
		txtDNSPort.addPropertyChangeListener(new PropertyChangeListener() {
			public void propertyChange(PropertyChangeEvent evt) {
			}
		});
		txtDNSPort.setText(tmpPort);
		GridBagConstraints gbc_txtDNSPort = new GridBagConstraints();
		gbc_txtDNSPort.anchor = GridBagConstraints.NORTH;
		gbc_txtDNSPort.fill = GridBagConstraints.HORIZONTAL;
		gbc_txtDNSPort.insets = new Insets(0, 0, 5, 0);
		gbc_txtDNSPort.gridx = 3;
		gbc_txtDNSPort.gridy = 1;
		panel.add(txtDNSPort, gbc_txtDNSPort);
		txtDNSPort.setColumns(10);
		GridBagConstraints gbc_chckbxStartDnsOn = new GridBagConstraints();
		gbc_chckbxStartDnsOn.anchor = GridBagConstraints.WEST;
		gbc_chckbxStartDnsOn.fill = GridBagConstraints.VERTICAL;
		gbc_chckbxStartDnsOn.gridx = 3;
		gbc_chckbxStartDnsOn.gridy = 2;
		panel.add(chckbxStartDnsOn, gbc_chckbxStartDnsOn);
		
		useDefaultIp = new JCheckBox("Use the above 'DNS Response IP' for all DNS responses excluding host entries below. ");
		useDefaultIp.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent arg0) {
				sb.setDefault(useDefaultIp.isSelected());
			}
		});
		useDefaultIp.setSelected(true);
		GridBagConstraints gbc_useDefaultIp = new GridBagConstraints();
		gbc_useDefaultIp.anchor = GridBagConstraints.WEST;
		gbc_useDefaultIp.insets = new Insets(0, 0, 5, 5);
		gbc_useDefaultIp.gridx = 2;
		gbc_useDefaultIp.gridy = 1;
		panel_2.add(useDefaultIp, gbc_useDefaultIp);
		
				
				lblCurrentIpAddress.setToolTipText("Double Click to add IP address to DNS Config");
				lblCurrentIpAddress.addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent arg0) {
						//Check for double click
						if(arg0.getClickCount()==2){
							String [] theSplits = lblCurrentIpAddress.getText().split(":");
							String ip = theSplits[1];
							if(ip!=null){
								ip=ip.trim();
								dnsIpTxt.setText(ip);
							}
							
							
						}
					}
				});
				GridBagConstraints gbc_lblCurrentIpAddress = new GridBagConstraints();
				gbc_lblCurrentIpAddress.anchor = GridBagConstraints.NORTH;
				gbc_lblCurrentIpAddress.fill = GridBagConstraints.HORIZONTAL;
				gbc_lblCurrentIpAddress.insets = new Insets(0, 0, 5, 5);
				gbc_lblCurrentIpAddress.gridx = 1;
				gbc_lblCurrentIpAddress.gridy = 2;
				panel_2.add(lblCurrentIpAddress, gbc_lblCurrentIpAddress);
				
				
						lblCurrentIpAddress.setForeground(Color.BLUE);
						lblCurrentIpAddress.setText("Current Ip Address: " + local );
		
		JLabel lblNewLabel_1 = new JLabel("             Left unchecked the real IP address will be used instead.");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_1.gridx = 2;
		gbc_lblNewLabel_1.gridy = 2;
		panel_2.add(lblNewLabel_1, gbc_lblNewLabel_1);
		
		JTextArea txtIfList = new JTextArea();
		GridBagConstraints gbc_txtIfList = new GridBagConstraints();
		gbc_txtIfList.insets = new Insets(0, 0, 0, 5);
		gbc_txtIfList.fill = GridBagConstraints.BOTH;
		gbc_txtIfList.gridx = 1;
		gbc_txtIfList.gridy = 3;
		panel_2.add(txtIfList, gbc_txtIfList);
		txtIfList.setEditable(false);
		txtIfList.setWrapStyleWord(true);
		txtIfList.setText(getInterfaceList());
		
		JPanel panel_4 = new JPanel();
		panel_4.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Custom Hosts file", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
		GridBagConstraints gbc_panel_4 = new GridBagConstraints();
		gbc_panel_4.insets = new Insets(0, 0, 0, 5);
		gbc_panel_4.fill = GridBagConstraints.BOTH;
		gbc_panel_4.gridx = 2;
		gbc_panel_4.gridy = 3;
		panel_2.add(panel_4, gbc_panel_4);
		GridBagLayout gbl_panel_4 = new GridBagLayout();
		gbl_panel_4.columnWidths = new int[]{12, 0};
		gbl_panel_4.rowHeights = new int[]{28, 0};
		gbl_panel_4.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_4.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_4.setLayout(gbl_panel_4);
		
		JTextArea dnsHosts = new JTextArea();
		dnsHosts.setText(this.readHosts());
		dnsHosts.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent arg0) {
				saveHosts(dnsHosts.getText());
			}
		});
		GridBagConstraints gbc_dnsHosts = new GridBagConstraints();
		gbc_dnsHosts.fill = GridBagConstraints.BOTH;
		gbc_dnsHosts.gridx = 0;
		gbc_dnsHosts.gridy = 0;
		panel_4.add(dnsHosts, gbc_dnsHosts);
	
		//tbm = (DefaultTableModel)ListTable.getModel();
		tbm = new DefaultTableModel(){
			 @Override
			    public boolean isCellEditable(int row, int column) {
			       if(column == 0)
			    	   return true;
			       else 
			    	   return false;
			    }
			
		};
		
		String header[] = new String[]{"Enable","Listener","Server Address", "Server Port","Cert Host","SSL"};
		tbm.setColumnIdentifiers(header);
		
		tbm.addTableModelListener(new TableModelListener() {

			@SuppressWarnings("static-access")
			@Override
			public void tableChanged(TableModelEvent e) {

				///OK something changed in the table... it could be a new row added or 
				
				if(e.getType()==e.UPDATE){
					int rowid = ListTable.getSelectedRow();
					//System.out.println("Updated Table");
					//update create 
					if(((Boolean)tbm.getValueAt(rowid, 0))){
						//Check if the port is in use
						int listport = Integer.parseInt((String)tbm.getValueAt(rowid, 1));
						if(!GenericMiTMServer.available(listport)){
							tbm.setValueAt(false, rowid, 0);
							Callbacks.printOutput("Port is already in use or port is outside range.");
						}else{
							
							GenericMiTMServer mtm = new GenericMiTMServer((Boolean)tbm.getValueAt(rowid, 5), Callbacks);
							//TODO: Add validation
							mtm.ListenPort = listport;
							mtm.ServerPort = Integer.parseInt((String)tbm.getValueAt(rowid, 3));
							mtm.CertHostName = (String)tbm.getValueAt(rowid, 4);
							mtm.ServerAddress = (String) tbm.getValueAt(rowid, 2);
							mtm.setPythonMange( chckbxEnablePythonMangler.isSelected() );
							mtm.addEventListener(NonHttpUI.this);
							mtm.addPyEventListener(NonHttpUI.this);
							if(btnIntercept.getText().endsWith("ON"))
								mtm.setIntercept(true);
							
							if(isC2S.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_C2S);
							else if(isS2C.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_S2C);
							else if(isBoth.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_BOTH);
							
							//threads.put(mtm.ListenPort, mtm); /// track threads by the listening port
							threads.put(rowid, mtm); /// track threads by the rowid
							Thread t = new Thread(mtm);
							t.start();
						}
					}else{ //delete a server thread
						/*int lPort = Integer.parseInt((String)tbm.getValueAt(rowid, 1));
						GenericMiTMServer mtm = ((GenericMiTMServer)threads.get(lPort));*/
						GenericMiTMServer mtm = ((GenericMiTMServer)threads.get(rowid));
						if(mtm != null){
							mtm.KillThreads();
							threads.remove(rowid);
						}
					}
				}


			}
		});
		
		
		
		
		//#####################################################################################
	    // Match and replace rules for  Options tab
		String rules = getMatchRules();
		if(rules.equals("")){
			rules = "# '#' will comment out the line\r\n"
					+ "# Normal String replace rules are in the following format:\r\n"
					+ "#\r\n"
					+ "# * MatchStr||ReplaceStr\r\n"
					+ "#\r\n"
					+ "# You can also match hex in the following format:\r\n"
					+ "#\r\n"
					+ "# * 0x11223344||0x556677"
					+ "\r\n"
					+ "# You can also specify direction with a 3rd argument:\r\n"
					+ "# There are 3 options: both, c2sOnly, s2cOnly\r\n"
					+ "#\r\n"
					+ "# For example to modify only client to server traffic\r\n"
					+ "# * 0x11223344||0x556677||c2sOnly";
					
		}
		
		Callbacks.customizeUiComponent(Options);

		//#####################################################################################
	    // SetUp table  TCP Log History Tab
		ntbm = new NonHTTPTableModel();
		ntbm.initDB();
		ntbm.requestViewer = Callbacks.createMessageEditor(ntbm,false);
		ntbm.originalViewer = Callbacks.createMessageEditor(ntbm,false);
		GridBagLayout gbl_Intercept = new GridBagLayout();
		gbl_Intercept.columnWidths = new int[]{122, 0};
		gbl_Intercept.rowHeights = new int[]{29, 0, 0};
		gbl_Intercept.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_Intercept.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		Intercept.setLayout(gbl_Intercept);

		JPanel panel_3 = new JPanel();
		GridBagConstraints gbc_panel_3 = new GridBagConstraints();
		gbc_panel_3.insets = new Insets(0, 0, 5, 0);
		gbc_panel_3.fill = GridBagConstraints.BOTH;
		gbc_panel_3.gridx = 0;
		gbc_panel_3.gridy = 0;
		Intercept.add(panel_3, gbc_panel_3);
		GridBagLayout gbl_panel_3 = new GridBagLayout();
		gbl_panel_3.columnWidths = new int[]{122, 56, 56, 60, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_3.rowHeights = new int[]{29, 0};
		gbl_panel_3.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_3.rowWeights = new double[]{0.0, Double.MIN_VALUE};
		panel_3.setLayout(gbl_panel_3);
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		splitPane.setBounds(6, 238, 989, 462);
		logTable = new Table(ntbm);
		//ColoredTableCellRenderer ctcr = new ColoredTableCellRenderer();
		//logTable.setDefaultRenderer(String.class, ctcr);
		logTable.setCellSelectionEnabled(true);
		logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		logTable.setFont(new Font("SansSerif", Font.PLAIN, 16));
		logTable.setBackground(SystemColor.text);
		
		JScrollPane logscrollPane = new JScrollPane(logTable);
		splitPane.setLeftComponent(logscrollPane);
		
		
		JPopupMenu jpm = new JPopupMenu();
		JMenuItem menuItem = new JMenuItem("Send To Comparer");
		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Callbacks.sendToComparer(ntbm.requestViewer.getMessage());
			}
		});
		jpm.add(menuItem);
		

		
		JPanel panel_5 = new JPanel();
		panel_5.setBorder(null);
		splitPane.setRightComponent(panel_5);
		GridBagLayout gbl_panel_5 = new GridBagLayout();
		gbl_panel_5.columnWidths = new int[]{115, 658, 0};
		gbl_panel_5.rowHeights = new int[]{35, 123, 0};
		gbl_panel_5.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_5.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		panel_5.setLayout(gbl_panel_5);
		
		// This button even will set focus on the currently selected tcp message.
		// This is usefull when several messages scroll across the table. It becomes
		// easy to loose your place.
		JButton btnGoBack = new JButton("Go To Selected");
		btnGoBack.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedRow = logTable.getSelectedRow();
				logTable.requestFocus();
				logTable.changeSelection(selectedRow,0,false, false);
			}
		});
		GridBagConstraints gbc_btnGoBack = new GridBagConstraints();
		gbc_btnGoBack.anchor = GridBagConstraints.WEST;
		gbc_btnGoBack.fill = GridBagConstraints.VERTICAL;
		gbc_btnGoBack.insets = new Insets(0, 0, 5, 5);
		gbc_btnGoBack.gridx = 0;
		gbc_btnGoBack.gridy = 0;
		panel_5.add(btnGoBack, gbc_btnGoBack);
		
		// UI Element to display the current selection in the tcp log
		lblSelected = new JLabel("Selected");
		GridBagConstraints gbc_lblSelected = new GridBagConstraints();
		gbc_lblSelected.fill = GridBagConstraints.BOTH;
		gbc_lblSelected.insets = new Insets(0, 0, 5, 0);
		gbc_lblSelected.gridx = 1;
		gbc_lblSelected.gridy = 0;
		panel_5.add(lblSelected, gbc_lblSelected);
		//This allows the table model to update the label text when an element is selected.
		ntbm.label = lblSelected;
		
		JTabbedPane tabs = new JTabbedPane();
		GridBagConstraints gbc_tabs = new GridBagConstraints();
		gbc_tabs.anchor = GridBagConstraints.WEST;
		gbc_tabs.gridwidth = 2;
		gbc_tabs.fill = GridBagConstraints.BOTH;
		gbc_tabs.insets = new Insets(0, 0, 0, 5);
		gbc_tabs.gridx = 0;
		gbc_tabs.gridy = 1;
		panel_5.add(tabs, gbc_tabs);
		
		

		//Decorate Tabs to match Burp message editor
		tabs.addTab("Message", ntbm.requestViewer.getComponent());
		tabs.addTab("Original", ntbm.originalViewer.getComponent());
		
		
	
		
		Callbacks.customizeUiComponent(History);
		
		
		
		
		
		//#####################################################################################
	    // SetUp UI for Interceptor tab
		btnIntercept = new JButton("Intercept is OFF");
		GridBagConstraints gbc_btnIntercept = new GridBagConstraints();
		gbc_btnIntercept.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnIntercept.insets = new Insets(0, 0, 0, 5);
		gbc_btnIntercept.gridx = 0;
		gbc_btnIntercept.gridy = 0;
		panel_3.add(btnIntercept, gbc_btnIntercept);
		btnIntercept.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				boolean toggle=false;
				if(btnIntercept.getText().endsWith("OFF")){
					btnIntercept.setText("Intercept is ON");
					toggle=true;
				}else{
					btnIntercept.setText("Intercept is OFF");
					toggle=false;
				}

				for(GenericMiTMServer svr : threads.values()){
					svr.setIntercept(toggle);
				}

			}
		});
		btnIntercept.setBounds(878, 205, 117, 29);

		JButton btnForward = new JButton("Forward");
		btnForward.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				synchronized (intbm) {
					isC2S.setBackground(UIManager.getColor("CheckBoxMenuItem.selectionBackground"));
					isS2C.setBackground(UIManager.getColor("CheckBoxMenuItem.selectionBackground"));
					intbm.notify();

				}
			}
		});
		GridBagConstraints gbc_btnForward = new GridBagConstraints();
		gbc_btnForward.anchor = GridBagConstraints.WEST;
		gbc_btnForward.insets = new Insets(0, 0, 0, 5);
		gbc_btnForward.gridx = 1;
		gbc_btnForward.gridy = 0;
		panel_3.add(btnForward, gbc_btnForward);

		isC2S = new JRadioButton("C2S");
		isC2S.setFont(new Font("Lucida Grande", Font.PLAIN, 13));
		isC2S.setBackground(UIManager.getColor("InternalFrame.paletteBackground"));
		isC2S.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for(GenericMiTMServer svr : threads.values()){
					svr.setInterceptDir(svr.INTERCEPT_C2S);
				}

			}
		});
		buttonGroup.add(isC2S);
		GridBagConstraints gbc_isC2S = new GridBagConstraints();
		gbc_isC2S.anchor = GridBagConstraints.WEST;
		gbc_isC2S.insets = new Insets(0, 0, 0, 5);
		gbc_isC2S.gridx = 3;
		gbc_isC2S.gridy = 0;
		panel_3.add(isC2S, gbc_isC2S);
		isC2S.setBounds(668, 206, 56, 23);

		isS2C = new JRadioButton("S2C");
		isS2C.setFont(new Font("Lucida Grande", Font.PLAIN, 13));
		isS2C.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for(GenericMiTMServer svr : threads.values()){
					svr.setInterceptDir(svr.INTERCEPT_S2C);
				}
			}
		});
		buttonGroup.add(isS2C);
		GridBagConstraints gbc_IsS2C = new GridBagConstraints();
		gbc_IsS2C.anchor = GridBagConstraints.WEST;
		gbc_IsS2C.insets = new Insets(0, 0, 0, 5);
		gbc_IsS2C.gridx = 4;
		gbc_IsS2C.gridy = 0;
		panel_3.add(isS2C, gbc_IsS2C);
		isS2C.setBounds(734, 206, 56, 23);

		isBoth = new JRadioButton("Both");
		isBoth.setFont(new Font("Lucida Grande", Font.PLAIN, 14));
		isBoth.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for(GenericMiTMServer svr : threads.values()){
					svr.setInterceptDir(svr.INTERCEPT_BOTH);
				}
			}
		});
		buttonGroup.add(isBoth);
		GridBagConstraints gbc_isBoth = new GridBagConstraints();
		gbc_isBoth.insets = new Insets(0, 0, 0, 5);
		gbc_isBoth.anchor = GridBagConstraints.WEST;
		gbc_isBoth.gridx = 5;
		gbc_isBoth.gridy = 0;
		panel_3.add(isBoth, gbc_isBoth);
		isBoth.setSelected(true);
		isBoth.setBounds(800, 206, 66, 23);

		interceptInfo = new JTextField();
		interceptInfo.setEditable(false);
		GridBagConstraints gbc_interceptInfo = new GridBagConstraints();
		gbc_interceptInfo.fill = GridBagConstraints.HORIZONTAL;
		gbc_interceptInfo.gridx = 10;
		gbc_interceptInfo.gridy = 0;
		panel_3.add(interceptInfo, gbc_interceptInfo);
		interceptInfo.setColumns(10);
		
		
		JTabbedPane interceptPane = new JTabbedPane(JTabbedPane.TOP);
		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 1;
		intbm = new NonHTTPTableModel();
		intbm.requestViewer = Callbacks.createMessageEditor(intbm,true);
		
		//This decorates the intercept tabs to be like brup message tables
		interceptPane.addTab("Message", intbm.requestViewer.getComponent());
		Intercept.add(interceptPane, gbc_tabbedPane);
		
		Callbacks.customizeUiComponent(Intercept);
		
		
		
		//#####################################################################################
		// Setup UI for DNS log
		JScrollPane DNSRequests = new JScrollPane();
		DnsListTable = new JTable(){
			@Override
			public Class getColumnClass(int column) {
				switch (column) {
				case 0:
					return String.class;
				case 1:
					return String.class;
				default:
					return String.class;
				}
			}
		};
		DnsListTable.setFont(new Font("SansSerif", Font.PLAIN, 16));

		DNSRequests.setViewportView(DnsListTable);
		
		dnstTbm = (DefaultTableModel)DnsListTable.getModel();
		String DNSheader[] = new String[]{"Time","Domain","Resolved Ip", "Client Address", "Client Name"};
		dnstTbm.setColumnIdentifiers(DNSheader);
		
	

		
		//#####################################################################################
		// Finalizing Setup functions
		
		
		if(AUTOSTART){
			btnStartDns.setText("Stop DNS");
			btnStartDns.setBackground(Color.GREEN);
			isDNSRunning = true;
			//lblStatusDNS.setText("DNS ON");
		}
		if(this.getProperties("autostart","false").equals("true"))
			chckbxStartDnsOn.setSelected(true);
		else
			chckbxStartDnsOn.setSelected(false);
		
		// Update the network interface information
		updateInterfaceInformation();
		// order the tabs
		BurpTabs.addTab("TCP Intercept", Intercept);
		BurpTabs.addTab("TCP History", splitPane);
		JPanel Automation = new JPanel();
		BurpTabs.addTab("Automation", null, Automation, null);
		Automation.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Match and Replace Rules", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_Automation = new GridBagLayout();
		gbl_Automation.columnWidths = new int[]{472, 0};
		gbl_Automation.rowHeights = new int[]{0, 0};
		gbl_Automation.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_Automation.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		Automation.setLayout(gbl_Automation);
		PythonMangler pm = new PythonMangler();
		
		JSplitPane splitPane_1 = new JSplitPane();
		splitPane_1.setResizeWeight(0.5);
		splitPane_1.setOneTouchExpandable(true);
		splitPane_1.setOrientation(JSplitPane.VERTICAL_SPLIT);
		GridBagConstraints gbc_splitPane_1 = new GridBagConstraints();
		gbc_splitPane_1.fill = GridBagConstraints.BOTH;
		gbc_splitPane_1.gridx = 0;
		gbc_splitPane_1.gridy = 0;
		Automation.add(splitPane_1, gbc_splitPane_1);
		
		JPanel panel_8 = new JPanel();
		splitPane_1.setRightComponent(panel_8);
		GridBagLayout gbl_panel_8 = new GridBagLayout();
		gbl_panel_8.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_panel_8.rowHeights = new int[]{0, 0, 0};
		gbl_panel_8.columnWeights = new double[]{0.0, 0.0, 1.0, 1.0, Double.MIN_VALUE};
		gbl_panel_8.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		panel_8.setLayout(gbl_panel_8);
		
		chckbxEnablePythonMangler = new JCheckBox("Enable Python Mangler");
		GridBagConstraints gbc_chckbxEnablePythonMangler = new GridBagConstraints();
		gbc_chckbxEnablePythonMangler.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxEnablePythonMangler.gridx = 0;
		gbc_chckbxEnablePythonMangler.gridy = 0;
		panel_8.add(chckbxEnablePythonMangler, gbc_chckbxEnablePythonMangler);
		
		JButton btnImportPython = new JButton("Import Python");
		GridBagConstraints gbc_btnImportPython = new GridBagConstraints();
		gbc_btnImportPython.insets = new Insets(0, 0, 5, 5);
		gbc_btnImportPython.gridx = 1;
		gbc_btnImportPython.gridy = 0;
		panel_8.add(btnImportPython, gbc_btnImportPython);
		
		JButton btnExportPython = new JButton("Export Python");
		GridBagConstraints gbc_btnExportPython = new GridBagConstraints();
		gbc_btnExportPython.anchor = GridBagConstraints.WEST;
		gbc_btnExportPython.insets = new Insets(0, 0, 5, 5);
		gbc_btnExportPython.gridx = 2;
		gbc_btnExportPython.gridy = 0;
		panel_8.add(btnExportPython, gbc_btnExportPython);
		
		JButton btnClearConsole = new JButton("Clear Console");
		btnClearConsole.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				PythonConsole.setText("");
			}
		});
		GridBagConstraints gbc_btnClearConsole = new GridBagConstraints();
		gbc_btnClearConsole.anchor = GridBagConstraints.EAST;
		gbc_btnClearConsole.insets = new Insets(0, 0, 5, 0);
		gbc_btnClearConsole.gridx = 3;
		gbc_btnClearConsole.gridy = 0;
		panel_8.add(btnClearConsole, gbc_btnClearConsole);
		
		JSplitPane splitPane_2 = new JSplitPane();
		splitPane_2.setResizeWeight(0.5);
		GridBagConstraints gbc_splitPane_2 = new GridBagConstraints();
		gbc_splitPane_2.fill = GridBagConstraints.BOTH;
		gbc_splitPane_2.gridwidth = 4;
		gbc_splitPane_2.gridx = 0;
		gbc_splitPane_2.gridy = 1;
		panel_8.add(splitPane_2, gbc_splitPane_2);
		
		JScrollPane scrollPane_2 = new JScrollPane();
		splitPane_2.setLeftComponent(scrollPane_2);
		
		pythonText = new JTextArea();
		scrollPane_2.setViewportView(pythonText);
		pythonText.setTabSize(3);
		pythonText.setBackground(new Color(44, 62, 80));
		pythonText.setFont(new Font("Lucida Console", Font.PLAIN, 15));
		pythonText.setForeground(Color.WHITE);
		pythonText.setWrapStyleWord(true);
		pythonText.setLineWrap(true);
		pythonText.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent arg0) {
				PythonMangler pm = new PythonMangler();
				pm.setPyCode(pythonText.getText());
			}
		});
		pythonText.setText(pm.getPyCode());
		
		JScrollPane scrollPane_3 = new JScrollPane();
		splitPane_2.setRightComponent(scrollPane_3);
		
		PythonConsole = new JEditorPane();
		PythonConsole.setEditable(false);
		PythonConsole.setContentType("text/html");
		
		scrollPane_3.setViewportView(PythonConsole);
		
		JPanel panel_6 = new JPanel();
		splitPane_1.setLeftComponent(panel_6);
		GridBagLayout gbl_panel_6 = new GridBagLayout();
		gbl_panel_6.columnWidths = new int[]{44, 12, 0};
		gbl_panel_6.rowHeights = new int[]{0, 0, 0};
		gbl_panel_6.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_6.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		panel_6.setLayout(gbl_panel_6);
		
		errorMsg = new JLabel("");
		GridBagConstraints gbc_errorMsg = new GridBagConstraints();
		gbc_errorMsg.fill = GridBagConstraints.HORIZONTAL;
		gbc_errorMsg.insets = new Insets(0, 0, 5, 0);
		gbc_errorMsg.gridx = 1;
		gbc_errorMsg.gridy = 0;
		panel_6.add(errorMsg, gbc_errorMsg);
		errorMsg.setForeground(Color.RED);
		
		JScrollPane scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 1;
		panel_6.add(scrollPane, gbc_scrollPane);
		
		txtRules = new JTextArea();
		txtRules.setTabSize(3);
		scrollPane.setViewportView(txtRules);
		txtRules.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				updateMatchRules();
				
			}
		});
		txtRules.setText(rules);
		btnExportPython.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				FileDialog fileDialog = new FileDialog(new Frame(), "Save", FileDialog.SAVE);
				fileDialog.setFilenameFilter(new FilenameFilter() {
				    public boolean accept(File dir, String name) {
				        return name.endsWith(".py");
				    }
				});
				fileDialog.setVisible(true);
				
				String filename = fileDialog.getDirectory() + fileDialog.getFile();
				if(filename != null){
					File f = new File(filename);
					if(!f.exists()){
						try {
							f.createNewFile();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					Path p = Paths.get(filename);
					Charset charset = Charset.forName("UTF-8");
					try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
						writer.write(pythonText.getText());
					}catch(Exception ex){
						ex.printStackTrace();
					}
				}
			}
		});
		btnImportPython.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				FileDialog fileDialog = new FileDialog(new Frame(), "Import", FileDialog.LOAD);
				fileDialog.setFilenameFilter(new FilenameFilter() {
				    public boolean accept(File dir, String name) {
				        return name.endsWith(".py");
				    }
				});
				fileDialog.setVisible(true);
				String filename = fileDialog.getDirectory() + fileDialog.getFile();
				if(filename != null){
					Path p = Paths.get(filename);
					
					try (BufferedReader reader = Files.newBufferedReader(p)) {
						String line = "";
						String code="";
						
						while( (line = reader.readLine()) != null ){
							code += line + "\r\n";
						}
						pythonText.setText(code);
						PythonMangler pm = new PythonMangler();
						pm.setPyCode(code);
						
						
					}catch(Exception ex){
						ex.printStackTrace();
					}
				}
			        
			}
		});
		chckbxEnablePythonMangler.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				for(GenericMiTMServer svr : threads.values()){
					svr.setPythonMange(chckbxEnablePythonMangler.isSelected());
				}
			}
		});
		BurpTabs.addTab("DNS History", null, DNSRequests, null);
		BurpTabs.add("Server Config", Options);
		
		//#####################################################################################
	    // Mitm Listner tables and controls for  Options tab
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Non HTTP Proxy Settings", TitledBorder.LEADING, TitledBorder.TOP, null, UIManager.getColor("CheckBoxMenuItem.selectionBackground")));
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.fill = GridBagConstraints.BOTH;
		gbc_panel_1.gridx = 0;
		gbc_panel_1.gridy = 1;
		Options.add(panel_1, gbc_panel_1);
				GridBagLayout gbl_panel_1 = new GridBagLayout();
				gbl_panel_1.columnWidths = new int[]{85, 157, 141, 83, 75, 40, 133, 117, 117, 0};
				gbl_panel_1.rowHeights = new int[]{22, 28, 29, 0, 0};
				gbl_panel_1.columnWeights = new double[]{0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
				gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
				panel_1.setLayout(gbl_panel_1);
						
						/// Buttons for Clear History, export database, import database, add proxy, remove proxy
						JButton btnAdd = new JButton("Add");
						GridBagConstraints gbc_btnAdd = new GridBagConstraints();
						gbc_btnAdd.fill = GridBagConstraints.BOTH;
						gbc_btnAdd.insets = new Insets(0, 0, 5, 5);
						gbc_btnAdd.gridheight = 2;
						gbc_btnAdd.gridx = 0;
						gbc_btnAdd.gridy = 0;
						panel_1.add(btnAdd, gbc_btnAdd);
						btnAdd.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent arg0) {
								int lPort = Integer.parseInt(LstnPort.getText());
								/*if(threads.containsKey(lPort))
									Callbacks.printOutput("Listener Already Exits");
								else{*/
								Vector<Object> vec = new Vector<Object>();

								vec.add(false);
								vec.add(LstnPort.getText());
								vec.add(SvrAddr.getText());
								vec.add(SvrPort.getText());
								vec.add(certName.getText());
								if(isSSL.isSelected())
									vec.add(true);
								else 
									vec.add(false);

								tbm.addRow(vec);
								int rowInserted=tbm.getRowCount()-1;
								tbm.fireTableRowsInserted(rowInserted,rowInserted);
									
								//}

							}
							
						});
						
						JLabel lblcertName = new JLabel("Certificate  HostName:");
						GridBagConstraints gbc_lblcertName = new GridBagConstraints();
						gbc_lblcertName.anchor = GridBagConstraints.SOUTH;
						gbc_lblcertName.fill = GridBagConstraints.HORIZONTAL;
						gbc_lblcertName.insets = new Insets(0, 0, 5, 5);
						gbc_lblcertName.gridx = 1;
						gbc_lblcertName.gridy = 0;
						panel_1.add(lblcertName, gbc_lblcertName);
				
						
				
						JLabel lblAddress = new JLabel("Server Address:");
						GridBagConstraints gbc_lblAddress = new GridBagConstraints();
						gbc_lblAddress.anchor = GridBagConstraints.SOUTHWEST;
						gbc_lblAddress.insets = new Insets(0, 0, 5, 5);
						gbc_lblAddress.gridx = 2;
						gbc_lblAddress.gridy = 0;
						panel_1.add(lblAddress, gbc_lblAddress);
						
						JLabel lblLstnPort = new JLabel("Server Port:");
						GridBagConstraints gbc_lblLstnPort = new GridBagConstraints();
						gbc_lblLstnPort.anchor = GridBagConstraints.SOUTH;
						gbc_lblLstnPort.fill = GridBagConstraints.HORIZONTAL;
						gbc_lblLstnPort.insets = new Insets(0, 0, 5, 5);
						gbc_lblLstnPort.gridx = 3;
						gbc_lblLstnPort.gridy = 0;
						panel_1.add(lblLstnPort, gbc_lblLstnPort);
				
						JLabel lblPort = new JLabel("Listen Port:");
						GridBagConstraints gbc_lblPort = new GridBagConstraints();
						gbc_lblPort.anchor = GridBagConstraints.SOUTH;
						gbc_lblPort.fill = GridBagConstraints.HORIZONTAL;
						gbc_lblPort.insets = new Insets(0, 0, 5, 5);
						gbc_lblPort.gridwidth = 2;
						gbc_lblPort.gridx = 4;
						gbc_lblPort.gridy = 0;
						panel_1.add(lblPort, gbc_lblPort);
				
				isSSL = new JCheckBox("SSL - (Export Burp's CACert as pkcs12 with  password 'changeit'. ");
				GridBagConstraints gbc_isSSL = new GridBagConstraints();
				gbc_isSSL.anchor = GridBagConstraints.NORTH;
				gbc_isSSL.fill = GridBagConstraints.HORIZONTAL;
				gbc_isSSL.insets = new Insets(0, 0, 5, 0);
				gbc_isSSL.gridheight = 2;
				gbc_isSSL.gridwidth = 4;
				gbc_isSSL.gridx = 5;
				gbc_isSSL.gridy = 0;
				panel_1.add(isSSL, gbc_isSSL);
				
				certName = new JTextField();
				certName.setText("www.example.com");
				GridBagConstraints gbc_certName = new GridBagConstraints();
				gbc_certName.anchor = GridBagConstraints.NORTH;
				gbc_certName.fill = GridBagConstraints.HORIZONTAL;
				gbc_certName.insets = new Insets(0, 0, 5, 5);
				gbc_certName.gridx = 1;
				gbc_certName.gridy = 1;
				panel_1.add(certName, gbc_certName);
				certName.setColumns(10);
				SvrAddr = new JTextField();
				SvrAddr.setText("127.0.0.1");
				GridBagConstraints gbc_SvrAddr = new GridBagConstraints();
				gbc_SvrAddr.anchor = GridBagConstraints.NORTH;
				gbc_SvrAddr.fill = GridBagConstraints.HORIZONTAL;
				gbc_SvrAddr.insets = new Insets(0, 0, 5, 5);
				gbc_SvrAddr.gridx = 2;
				gbc_SvrAddr.gridy = 1;
				panel_1.add(SvrAddr, gbc_SvrAddr);
				SvrAddr.setColumns(10);
										
										JButton btnImportHistory = new JButton("Import History");
										btnImportHistory.addActionListener(new ActionListener() {
											public void actionPerformed(ActionEvent e) {
												//String fs =  System.getProperty("file.separator");
												//String resultFile = System.getProperty("user.dir") + fs +"requests.sqlite";
												String path = System.getProperty("user.home");
												String resultFile = path + "/.NoPEProxy/requests.sqlite";
												Frame fr = new Frame();
												FileDialog fd = new FileDialog(fr,"Import Database", FileDialog.LOAD);
												fd.setVisible(true);
												
												String imported = fd.getDirectory() +  fd.getFile();
												Path impPath = Paths.get(imported);
												Path localPath = Paths.get(resultFile);
												try {
													HibHelper.getSessionFactory().close();
													Thread.sleep(2000); // wait for the threads to close
													
													Files.copy(impPath, localPath, StandardCopyOption.REPLACE_EXISTING);
													//Delete The current table;
													int rowCount=ntbm.getRowCount();
													if(rowCount >0 ){
														for (int i=rowCount -1; i>=0; i--) {
															ntbm.log.remove(i);
															//ntbm.fireTableRowsDeleted(i, i);
														}
													}
													HibHelper.renew();
													LinkedList<LogEntry> list = LogEntry.restoreDB();
													for(LogEntry le : list){
														ntbm.log.add(le);
													}
													
													
													
												} catch (IOException e1) {
													Callbacks.printError(e1.getMessage());
												} catch (InterruptedException e1) {
													// TODO Auto-generated catch block
													e1.printStackTrace();
												}
												
											}
										});
										
												JButton btnRemoveProxy = new JButton("Remove Proxy");
												btnRemoveProxy.addActionListener(new ActionListener() {
													public void actionPerformed(ActionEvent e) {
														int rowid = ListTable.getSelectedRow();
														int lPort = Integer.parseInt((String)tbm.getValueAt(rowid, 1));
														if(threads.get(lPort) != null && threads.get(lPort).isRunning()){
															threads.get(lPort).KillThreads();
															threads.remove(lPort);
															
														}
														tbm.removeRow(rowid);
														tbm.fireTableRowsDeleted(rowid, rowid);
														
													}
												});
												
												SvrPort = new JTextField();
												SvrPort.setText("1001");
												GridBagConstraints gbc_SvrPort = new GridBagConstraints();
												gbc_SvrPort.anchor = GridBagConstraints.NORTH;
												gbc_SvrPort.fill = GridBagConstraints.HORIZONTAL;
												gbc_SvrPort.insets = new Insets(0, 0, 5, 5);
												gbc_SvrPort.gridx = 3;
												gbc_SvrPort.gridy = 1;
												panel_1.add(SvrPort, gbc_SvrPort);
												SvrPort.setColumns(10);
												
														LstnPort = new JTextField();
														LstnPort.setText("1000");
														GridBagConstraints gbc_LstnPort = new GridBagConstraints();
														gbc_LstnPort.anchor = GridBagConstraints.NORTH;
														gbc_LstnPort.fill = GridBagConstraints.HORIZONTAL;
														gbc_LstnPort.insets = new Insets(0, 0, 5, 5);
														gbc_LstnPort.gridx = 4;
														gbc_LstnPort.gridy = 1;
														panel_1.add(LstnPort, gbc_LstnPort);
														LstnPort.setColumns(10);
												
												JLabel lblNewLabel = new JLabel("Name the cert 'burpca.p12'  in Burp's installation folder)");
												GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
												gbc_lblNewLabel.anchor = GridBagConstraints.NORTH;
												gbc_lblNewLabel.fill = GridBagConstraints.HORIZONTAL;
												gbc_lblNewLabel.insets = new Insets(0, 0, 5, 0);
												gbc_lblNewLabel.gridwidth = 3;
												gbc_lblNewLabel.gridx = 6;
												gbc_lblNewLabel.gridy = 1;
												panel_1.add(lblNewLabel, gbc_lblNewLabel);
												GridBagConstraints gbc_btnRemoveProxy = new GridBagConstraints();
												gbc_btnRemoveProxy.anchor = GridBagConstraints.WEST;
												gbc_btnRemoveProxy.fill = GridBagConstraints.VERTICAL;
												gbc_btnRemoveProxy.insets = new Insets(0, 0, 5, 5);
												gbc_btnRemoveProxy.gridwidth = 2;
												gbc_btnRemoveProxy.gridx = 0;
												gbc_btnRemoveProxy.gridy = 2;
												panel_1.add(btnRemoveProxy, gbc_btnRemoveProxy);
										
										JButton btnAdd_1 = new JButton("Add 80 & 443 to Burp");
										btnAdd_1.setToolTipText("This addes invisible proxy listeners to Burp's normal HTTP proxy configureation.");
										btnAdd_1.addActionListener(new ActionListener() {
											public void actionPerformed(ActionEvent arg0) {
												//This is used to automagicaly add 80 and 443 invisible proxy listeners to burp's normal HTTP traffic listernes.
												// These ports are used with the DNS server to proxy HTTP requests normally through burp.
												String config = Callbacks.saveConfigAsJson("proxy.request_listeners");
												JSONParser parser = new JSONParser();
												try {
													JSONObject jsonObject = (JSONObject) parser.parse(config);
													JSONArray listeners = (JSONArray)((JSONObject)jsonObject.get("proxy")).get("request_listeners");
													JSONObject list80 = new JSONObject();
													list80.put("certificate_mode", "per_host");
													list80.put("running", true);
													list80.put("support_invisible_proxying", true);
													list80.put("listen_mode", "all_interfaces");
													list80.put("listener_port", 80);
													JSONObject list443 = (JSONObject) parser.parse(list80.toJSONString());
													list443.put("listener_port", 443);
													listeners.add(list80);
													listeners.add(list443);
													Callbacks.loadConfigFromJson(jsonObject.toJSONString());
													
													
												} catch (ParseException e) {
													// TODO Auto-generated catch block
													e.printStackTrace();
												}
												
												//Callbacks.loadConfigFromJson(arg0);
												
											}
										});
										GridBagConstraints gbc_btnAdd_1 = new GridBagConstraints();
										gbc_btnAdd_1.anchor = GridBagConstraints.EAST;
										gbc_btnAdd_1.gridwidth = 2;
										gbc_btnAdd_1.insets = new Insets(0, 0, 5, 5);
										gbc_btnAdd_1.gridx = 3;
										gbc_btnAdd_1.gridy = 2;
										panel_1.add(btnAdd_1, gbc_btnAdd_1);
										GridBagConstraints gbc_btnImportHistory = new GridBagConstraints();
										gbc_btnImportHistory.anchor = GridBagConstraints.EAST;
										gbc_btnImportHistory.fill = GridBagConstraints.VERTICAL;
										gbc_btnImportHistory.insets = new Insets(0, 0, 5, 5);
										gbc_btnImportHistory.gridx = 6;
										gbc_btnImportHistory.gridy = 2;
										panel_1.add(btnImportHistory, gbc_btnImportHistory);
										
										JButton btnSaveHistory = new JButton("Export History");
										btnSaveHistory.addActionListener(new ActionListener() {
											public void actionPerformed(ActionEvent e) {
												//String fs =  System.getProperty("file.separator");
												//String file = System.getProperty("user.dir") + fs +"requests.sqlite";
												String path = System.getProperty("user.home");
												String file = path + "/.NoPEProxy/requests.sqlite";
												Frame fr = new Frame();
												FileDialog fd = new FileDialog(fr,"Export File", FileDialog.SAVE);
												fd.setVisible(true);
												
												String exported = fd.getDirectory() +  fd.getFile();
												Path old = Paths.get(file);
												Path newFile = Paths.get(exported);
												try {
													Files.copy(old, newFile, StandardCopyOption.REPLACE_EXISTING);
												} catch (IOException e1) {
													Callbacks.printError(e1.getMessage());
												}
												
												
											
											}
										});
										GridBagConstraints gbc_btnSaveHistory = new GridBagConstraints();
										gbc_btnSaveHistory.fill = GridBagConstraints.BOTH;
										gbc_btnSaveHistory.insets = new Insets(0, 0, 5, 5);
										gbc_btnSaveHistory.gridx = 7;
										gbc_btnSaveHistory.gridy = 2;
										panel_1.add(btnSaveHistory, gbc_btnSaveHistory);
										
												JButton btnClearHistory = new JButton("Clear History");
												btnClearHistory.addActionListener(new ActionListener() {
													public void actionPerformed(ActionEvent e) {
														int rowCount=ntbm.getRowCount();
														if(rowCount <=0)
															return;

														for (int i=rowCount -1; i>=0; i--) {
															ntbm.log.remove(i);
															//ntbm.fireTableRowsDeleted(i, i);
														}
														LogEntry.clearTable();

													}
												});
												GridBagConstraints gbc_btnClearHistory = new GridBagConstraints();
												gbc_btnClearHistory.insets = new Insets(0, 0, 5, 0);
												gbc_btnClearHistory.fill = GridBagConstraints.BOTH;
												gbc_btnClearHistory.gridx = 8;
												gbc_btnClearHistory.gridy = 2;
												panel_1.add(btnClearHistory, gbc_btnClearHistory);
												
														JScrollPane scrollPane_1 = new JScrollPane();
														GridBagConstraints gbc_scrollPane_1 = new GridBagConstraints();
														gbc_scrollPane_1.fill = GridBagConstraints.BOTH;
														gbc_scrollPane_1.gridwidth = 9;
														gbc_scrollPane_1.gridx = 0;
														gbc_scrollPane_1.gridy = 3;
														panel_1.add(scrollPane_1, gbc_scrollPane_1);
														// Create the listener table and add it to the above scroll pane
														ListTable = new JTable(){
															@Override
															public Class getColumnClass(int column) {
																switch (column) {
																case 0:
																	return Boolean.class;
																case 1:
																	return Integer.class;
																case 2:
																	return Integer.class;
																case 3:
																	return String.class;
																case 4:
																	return String.class;
																case 5:
																	return Boolean.class;
																default:
																	return String.class;
																}
															}
														};
														scrollPane_1.setViewportView(ListTable);
														ListTable.setModel(tbm);
		// Add Tabs to main component
		add(BurpTabs);
		Callbacks.customizeUiComponent(BurpTabs);
		
		JPanel panel_7 = new JPanel();
		BurpTabs.addTab("About", null, panel_7, null);
		GridBagLayout gbl_panel_7 = new GridBagLayout();
		gbl_panel_7.columnWidths = new int[]{0, 0, 0, 0};
		gbl_panel_7.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_7.columnWeights = new double[]{0.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_panel_7.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_7.setLayout(gbl_panel_7);
		
		JLabel lblNopeProxy = new JLabel("NOn Http Protocol Extender (NoPE) Proxy");
		GridBagConstraints gbc_lblNopeProxy = new GridBagConstraints();
		gbc_lblNopeProxy.insets = new Insets(0, 0, 5, 5);
		gbc_lblNopeProxy.gridx = 1;
		gbc_lblNopeProxy.gridy = 1;
		panel_7.add(lblNopeProxy, gbc_lblNopeProxy);
		
		JLabel lblVersion = new JLabel("Version 1.4.3");
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.insets = new Insets(0, 0, 5, 5);
		gbc_lblVersion.gridx = 1;
		gbc_lblVersion.gridy = 2;
		panel_7.add(lblVersion, gbc_lblVersion);
		
		JLabel lblDevelopedByJosh = new JLabel("Developed By: Josh Summitt");
		GridBagConstraints gbc_lblDevelopedByJosh = new GridBagConstraints();
		gbc_lblDevelopedByJosh.insets = new Insets(0, 0, 5, 5);
		gbc_lblDevelopedByJosh.gridx = 1;
		gbc_lblDevelopedByJosh.gridy = 4;
		panel_7.add(lblDevelopedByJosh, gbc_lblDevelopedByJosh);
		
		JButton btnHttpgithubcomsummitt = new JButton("https://github.com/summitt");
		btnHttpgithubcomsummitt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					Desktop.getDesktop().browse(new URI("https://github.com/summitt"));
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (URISyntaxException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
		GridBagConstraints gbc_btnHttpgithubcomsummitt = new GridBagConstraints();
		gbc_btnHttpgithubcomsummitt.insets = new Insets(0, 0, 0, 5);
		gbc_btnHttpgithubcomsummitt.gridx = 1;
		gbc_btnHttpgithubcomsummitt.gridy = 6;
		panel_7.add(btnHttpgithubcomsummitt, gbc_btnHttpgithubcomsummitt);
		
		//Set DataUpdate Timer
		timer = new Timer();
		timer.scheduleAtFixedRate(new UpdateDBTask(queue,ntbm), 0, 2*1000);
	    //timer.schedule(new UpdateDBTask(queue,ntbm), 2 * 1000);
		
		


	}
//############################################################################################################################
// Supporting Functions
//############################################################################################################################
	private void saveHosts(String hosts){
		
		/*String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "hosts.txt";*/
		String path = System.getProperty("user.home");
		String file = path + "/.NoPEProxy/hosts.txt";
		File f = new File(file);
		if(!f.exists()){
			Callbacks.printOutput("missing hosts.txt.. creating it.");
			try {
				f.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return;
		}
		Path p = Paths.get(file);
		
		Charset charset = Charset.forName("UTF-8");
		try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
			writer.write(hosts);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	private String readHosts(){
		
		//String fs =  System.getProperty("file.separator");
		//String file = System.getProperty("user.dir") + fs + "hosts.txt";
		String path = System.getProperty("user.home");
		String file = path + "/.NoPEProxy/hosts.txt";
		File f = new File(file);
		if(!f.exists()){
			return "";
		}
		Path p = Paths.get(file);
		
		BufferedReader reader;
		String out="";
		try {
			reader = Files.newBufferedReader(p);
			
			String line="";
			while ((line = reader.readLine()) != null) {
				out+=line+"\r\n";
			}
		} catch (IOException e) {
			out="";
			e.printStackTrace();
		}
		
		return out;
	}
	private void updateMatchRules(){
	
		//String fs =  System.getProperty("file.separator");
		//String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
		String path = System.getProperty("user.home");
		String file = path + "/.NoPEProxy/nonHTTPmatch.txt";
		File f = new File(file);
		if(!f.exists()){
			Callbacks.printOutput("missing nonHTTPsmatch.txt.. creating it.");
			try {
				f.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return;
		}
		Path p = Paths.get(file);
		
		Charset charset = Charset.forName("UTF-8");
		try (BufferedWriter writer = Files.newBufferedWriter(p, charset)) {
			String rules= this.getTxtRules().getText();
			String [] rs = rules.split("\n");
			String error="";
			
			for(String r : rs){
				if(r.trim().equals("")){ // blank line
					writer.write("");
				}else if (r.startsWith("#")){ // a comment
					writer.write(r + "\n");
				}else if (r.contains("||") && r.split("\\|\\|").length ==2){ // 2 argument match
					writer.write(r + "\n");
				}else if (r.contains("||") && r.split("\\|\\|").length ==3 &&  r.split("\\|\\|")[2].matches("(both|c2sOnly|s2cOnly)")){ // 3 argument match
					writer.write(r + "\n");
				}else if (r.contains("||") && r.split("\\|\\|").length ==3){
					error = "3rd Argument must be 'both', 'c2sOnly', or 's2cOnly'";
				}else{
					error = "Rules Are Not Valid. Format: matchStr||replaceStr or 0x121212||0x131313";
					
				}
			}
			
			errorMsg.setText(error);
			
		
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	private String getMatchRules(){
		String out = "";
		//String fs =  System.getProperty("file.separator");
		//String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
		String path = System.getProperty("user.home");
		String file = path + "/.NoPEProxy/nonHTTPmatch.txt";
		File f = new File(file);
		if(!f.exists()){
			try {
				f.createNewFile();
			} catch (IOException e) {
				Callbacks.printError(e.getMessage());
			}
			Callbacks.printOutput("missing nonHTTPsmatch.txt");
			return "";
		}
		Path p = Paths.get(file);
		
		Charset charset = Charset.forName("UTF-8");
		try (BufferedReader reader = Files.newBufferedReader(p, charset)) {
		    String line = null;
		    while ((line = reader.readLine()) != null) {
		    	out += line + "\r\n";
		    }
		} catch (IOException x) {
		    System.err.format("IOException: %s%n", x);
		}
		return out;
		
	}
	
	private String getInterfaceList(){
		String out="";
		Enumeration e;
		try {
			e = NetworkInterface.getNetworkInterfaces();
			int ifCount =0;
			while(e.hasMoreElements())
			{
			    NetworkInterface n = (NetworkInterface) e.nextElement();
			    Enumeration ee = n.getInetAddresses();
			    while (ee.hasMoreElements())
			    {
			        InetAddress i = (InetAddress) ee.nextElement();
			        if(i.getHostAddress().matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")){
			        	out += ifCount++ +") " + n.getName() + " : " + i.getHostAddress() + " : " + (n.getHardwareAddress() != null ? Hex.toHexString(n.getHardwareAddress()) : "") + "\n";
			        	
			        	
			        }
			    
			    }
			    ifCount++;
			}
		} catch (SocketException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return out;
		
	}
	private void updateInterface(String state){

		this.updateProperties("interface", state);


	}
	private void updateProperties(String key, String value){
		Properties config = new Properties();
		try {
			//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
			String path = System.getProperty("user.home");
			File f = new File(path + "/.NoPEProxy/dns.properties");
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				File p = new File(path + "/.NoPEProxy");
				if(!p.exists())
					p.mkdir();
				f.createNewFile();
			}

			config.put(key, value);
			config.store(new FileOutputStream(f), null);

		} catch (FileNotFoundException e1) {

			e1.printStackTrace();
		} catch (IOException e1) {

			e1.printStackTrace();
		}
		
	}
	
	private String getProperties(String key){
		return this.getProperties(key,"");
	}
	private String getProperties(String key, String defaultValue){
		Properties config = new Properties();
		try {
			//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
			String path = System.getProperty("user.home");
			File f = new File(path + "/.NoPEProxy/dns.properties");
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				File p = new File(path + "/.NoPEProxy");
				if(!p.exists())
					p.mkdir();
				f.createNewFile();
			}
			return config.getProperty(key, defaultValue);
			

		} catch (FileNotFoundException e1) {

			e1.printStackTrace();
		} catch (IOException e1) {

			e1.printStackTrace();
		}
		return "";
		
	}

	private void updateAutoStart(boolean state){
		
		if(state)
			this.updateProperties("autoStart", "true");
		else
			this.updateProperties("autoStart", "false");
			

	}


	public boolean getAutoStart(){
		return AUTOSTART;
	}

	public void DNSStopped(){
		btnStartDns.setText("Start DNS");
		btnStartDns.setBackground(Color.RED);
		isDNSRunning = false;
		//lblStatusDNS.setText("DNS OFF");


	}

	public int getInterfaceNumber(){
		return IFNUM;
	}
	private void updateInterfaceInformation(){
		Enumeration e;
		try {
			e = NetworkInterface.getNetworkInterfaces();
			int ifCount =0;
			while(e.hasMoreElements())
			{
			    NetworkInterface n = (NetworkInterface) e.nextElement();
			    Enumeration ee = n.getInetAddresses();
			    while (ee.hasMoreElements())
			    {
			        InetAddress i = (InetAddress) ee.nextElement();
			        if(i.getHostAddress().matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")){
			        	Callbacks.printOutput(ifCount + ") " + n.getName() + " : " + i.getHostAddress() + " : " + (n.getHardwareAddress() != null ? Hex.toHexString(n.getHardwareAddress()) : ""));
			        	if(Integer.parseInt(IfTxtBox.getText()) == ifCount++){
			        		lblCurrentIpAddress.setText("Current Ip Address: " + i.getHostAddress());
			        		dnsIpTxt.setText(i.getHostAddress());
			        		
			        		break;
			        	}
			        	
			        }
			    
			    }
			    ifCount++;
			}
		} catch (SocketException e1) {
			Callbacks.printError(e1.getMessage());
		}
	}

//########################################################################################################################################################################
/// Event Stuff here
	private List _listeners = new ArrayList();
	private JCheckBox useDefaultIp;
	private JTextArea pythonText;
	private JCheckBox chckbxEnablePythonMangler;
	
	public synchronized void addEventListener(DNSConfigListener listener)	{
		_listeners.add(listener);
	}
	public synchronized void removeEventListener(DNSConfigListener listener)	{
		_listeners.remove(listener);
	}

	@SuppressWarnings("rawtypes")
	private synchronized void ToggleDNS(String Address, Integer Port){
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			DNSEvent evt = new DNSEvent(this);
			evt.setAddress(Address);
			evt.setPort(Port);
			((DNSConfigListener) i.next()).DNSToggle(evt);
		}
	}

	public synchronized void addEventListener(ProxyEventListener listener)	{
		_listeners.add(listener);
		//_listeners.remove(listener);
	}
	public synchronized void removeEventListener(ProxyEventListener listener)	{
		_listeners.remove(listener);
	}
	@Override
	public void DataReceived(ProxyEvent evt) {
		// Network data to the queue.
		// timer will process this every 2 seconds and add them to the log.
		queue.add(new LogEntry(evt.getData(),evt.getOriginalData(), evt.getSrcIP(), evt.getSrcPort(), evt.getDstIP(), evt.getDstPort(), evt.getDirection()));


	}
	@Override
	public void Intercepted(ProxyEvent evt, boolean isC2S) {

		byte [] origReq = evt.getData();
		intbm.requestViewer.setMessage(evt.getData(), true);
		if(isC2S){
			this.isC2S.setForeground(Color.red);
			this.isC2S.setFont(new Font("Lucida Grande", Font.BOLD, 13));
			interceptInfo.setText(evt.getSrcIP() + ":" + evt.getSrcPort() + " ==>> " + evt.getDstIP() + ":"+evt.getDstPort());	
			interceptInfo.setForeground(Color.blue);
		}
		else {
			this.isS2C.setForeground(Color.red);
			this.isS2C.setFont(new Font("Lucida Grande", Font.BOLD, 13));
			interceptInfo.setText(evt.getDstIP() + ":"+evt.getDstPort() + " <<== " + evt.getSrcIP() + ":" + evt.getSrcPort());
			interceptInfo.setForeground(new Color(0xE4, 0x31, 0x17));
		}

		synchronized (intbm) {
			try {
				
				intbm.wait();
				
				if(isC2S)
					evt.getMtm().forwardC2SRequest(intbm.requestViewer.getMessage());
				else
					evt.getMtm().forwardS2CRequest(intbm.requestViewer.getMessage());
				if(intbm.requestViewer.getMessage() == origReq)
					queue.add(new LogEntry(intbm.requestViewer.getMessage(), origReq, evt.getSrcIP(), evt.getSrcPort(), evt.getDstIP(), evt.getDstPort(), evt.getDirection()/*+" - Intercepted - Not Changed"*/));
				else
					queue.add(new LogEntry(intbm.requestViewer.getMessage(),origReq, evt.getSrcIP(), evt.getSrcPort(), evt.getDstIP(), evt.getDstPort(), "** "+evt.getDirection()+" ** - Edited"));
			
				//ntbm.fireTableRowsInserted(0, 0);
				intbm.requestViewer.setMessage(new byte[]{}, true);
				interceptInfo.setText("");
				this.isC2S.setForeground(Color.black);
				this.isS2C.setForeground(Color.black);
				this.isS2C.setFont(new Font("Lucida Grande", Font.PLAIN, 13));
				this.isC2S.setFont(new Font("Lucida Grande", Font.PLAIN, 13));

			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
		}



	}
	@Override
	public void NewDomainRequest(DNSTableEvent e) {
		String Domain = e.getDomain();
		String ClientIp = e.getClientIP();
		Vector<Object> vec = new Vector<Object>();
		Date now = Calendar.getInstance().getTime();
		vec.add(now.toString());
		vec.add(Domain);
		vec.add(e.getResponseIp());
		vec.add(ClientIp);
		vec.add(e.getHostName());
		int N = dnstTbm.getRowCount();
		for(int i=0; i< N; i++){
			String dname = dnstTbm.getValueAt(i, 1).toString();
			String ip = dnstTbm.getValueAt(i, 2).toString();
			if(ip.equals(ClientIp) && dname.equals(Domain)){
				dnstTbm.removeRow(i);
				break;
			}
		}
		
		dnstTbm.insertRow(0, vec);
		
	}
	@Override
	public void PythonMessages(PythonOutputEvent e) {
		
		String Output = "";
		if(e.getDirection().startsWith("Client"))
			Output += "<div style='background-color: #7f8c8d; color:white; font-family: 'Lucida Console', 'Lucida Sans Typewriter', monaco, 'Bitstream Vera Sans Mono', monospace;'>";
		else
			Output += "<div style='background-color: #2c3e50; color: white; font-family: 'Lucida Console', 'Lucida Sans Typewriter', monaco, 'Bitstream Vera Sans Mono', monospace;'>";
		Output +="Direction: " + e.getDirection() + " : " + new Date() + "<hr>";
		if(!e.getMessage().equals("")){
			Output += "<div style='color:#2ecc71; font-size: 14px;'>";
			Output += "###Messages:<br>";
			Output +=  e.getMessage().replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>");
			Output += "</div><br/>";
			
		}
		
		if(!e.getError().equals("")){
			Output += "<div style='color:#c0392b; font-size: 14px;'>";
			Output += "###Errors:<br>";
			Output += "<br>" + e.getError().replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>");
			Output += "<div><br/>";
		}
		Output+="</div>";
		//this.PythonConsole.setText(this.PythonConsole.getText() + "\n" +Output);
		HTMLDocument doc = (HTMLDocument)PythonConsole.getDocument();
		HTMLEditorKit editorKit = (HTMLEditorKit)PythonConsole.getEditorKit();
		
		try {
			editorKit.insertHTML(doc, doc.getLength(), Output, 0, 0, null);
		} catch (BadLocationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		System.out.println(e.getError());
		System.out.println(e.getMessage());
		
	}
	public JTextArea getTxtRules() {
		return txtRules;
	}
	
	public JTextField getTxtDNSPort() {
		return txtDNSPort;
	}
	public JLabel getLblSelected() {
		return lblSelected;
	}
	public JCheckBox getChckbxUseAboveIp() {
		return useDefaultIp;
	}
	public JTextArea getPythonText() {
		return pythonText;
	}
	public JCheckBox getChckbxEnablePythonMangler() {
		return chckbxEnablePythonMangler;
	}


}
