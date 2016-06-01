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
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
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
import org.bouncycastle.util.encoders.Hex;
import org.hibernate.Session;

import josh.dao.HibHelper;
import josh.dao.UpdateDBTask;
import josh.nonHttp.GenericMiTMServer;
import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.nonHttp.utils.LogEntry;
import josh.nonHttp.utils.NonHTTPTableModel;
import josh.nonHttp.utils.Table;
import josh.utils.events.DNSConfigListener;
import josh.utils.events.DNSTableEvent;
import josh.utils.events.DNSTableEventListener;


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
import java.awt.FileDialog;


@SuppressWarnings("serial")
public class NonHttpUI extends JPanel implements ProxyEventListener, DNSTableEventListener{

	public IBurpExtenderCallbacks Callbacks;
	public IExtensionHelpers Helpers;
	private final JButton btnStartDns;
	private boolean AUTOSTART = false;
	public boolean isDNSRunning = false;
	public boolean isLearning = false;
	public String DNSIP = "";
	private int IFNUM;
	JLabel lblCurrentIpAddress = new JLabel("Current Ip Address: ");
	JLabel lblStatusDNS;
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
	

	//GenericMiTMServer mtm;


	/**
	 * Create the frame.
	 */
	public NonHttpUI(IBurpExtenderCallbacks Callbacks, IExtensionHelpers Helpers) {
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
		
		//#####################################################################################
	    // Setup UI for Options tab
		Options.setLayout(null);
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "DNS Settings", TitledBorder.LEADING, TitledBorder.TOP, null, UIManager.getColor("CheckBoxMenuItem.selectionBackground")));
		panel_2.setBounds(7, 6, 545, 423);
		Options.add(panel_2);
		panel_2.setLayout(null);

		//#####################################################################################
	    // DNS Controls for  Options tab
		JPanel panel = new JPanel();
		panel.setBounds(71, 22, 422, 110);
		panel_2.add(panel);
		panel.setBorder(new LineBorder(new Color(0, 0, 0)));
		panel.setLayout(null);
		lblStatusDNS = new JLabel("DNS OFF");
		lblStatusDNS.setBounds(161, 210, 126, 16);
		panel.add(lblStatusDNS);
		btnStartDns = new JButton("Start DNS");
		btnStartDns.setBackground(Color.RED);
		btnStartDns.setToolTipText("DNS will respond to all requests with the IP address in Blue below.");
		btnStartDns.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ToggleDNS();
				if(isDNSRunning){


				}else{
					btnStartDns.setBackground(Color.GREEN);
					btnStartDns.setText("Stop DNS");
					isDNSRunning = true;
					lblStatusDNS.setText("DNS ON");
				}

			}
		});
		btnStartDns.setBounds(16, 9, 117, 29);
		panel.add(btnStartDns);

		final JCheckBox chckbxStartDnsOn = new JCheckBox("Start DNS on Start Up");
		chckbxStartDnsOn.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent arg0) {
				updateAutoStart(chckbxStartDnsOn.isSelected());
			}
		});

		chckbxStartDnsOn.setBounds(117, 81, 203, 23);
		panel.add(chckbxStartDnsOn);
		JLabel lblDnsIp = new JLabel("DNS IP:");
		lblDnsIp.setBounds(222, 14, 53, 16);
		panel.add(lblDnsIp);
		String local="---";
		

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

		dnsIpTxt.setBounds(282, 8, 134, 28);
		panel.add(dnsIpTxt);
		dnsIpTxt.setColumns(10);
		dnsIpTxt.setText(local);
		
		JLabel lblDnsport = new JLabel("DNSPort:");
		lblDnsport.setBounds(222, 44, 61, 16);
		panel.add(lblDnsport);
		
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
		String tmpPort = this.getProperties("dnsport");
		if(tmpPort == null || tmpPort.equals(""))
			tmpPort="5353";
		txtDNSPort.setText(tmpPort);
		txtDNSPort.setBounds(286, 39, 130, 26);
		panel.add(txtDNSPort);
		txtDNSPort.setColumns(10);

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


		IfTxtBox.setToolTipText("The interface number from the list below.");
		IfTxtBox.setText(""+IFNUM);
		IfTxtBox.setBounds(89, 44, 34, 28);
		panel.add(IfTxtBox);
		IfTxtBox.setColumns(10);

		JLabel lblInterface = new JLabel("Interface:");
		lblInterface.setBounds(16, 50, 61, 16);
		panel.add(lblInterface);
		
		JTextArea txtIfList = new JTextArea();
		txtIfList.setBounds(42, 172, 487, 223);
		panel_2.add(txtIfList);
		txtIfList.setEditable(false);
		txtIfList.setWrapStyleWord(true);
		txtIfList.setText(getInterfaceList());

		
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
		lblCurrentIpAddress.setBounds(53, 144, 279, 16);
		panel_2.add(lblCurrentIpAddress);


		lblCurrentIpAddress.setForeground(Color.BLUE);
		lblCurrentIpAddress.setText("Current Ip Address: " + local );

		JLabel lblSelectInterfaceNumber = new JLabel("Select Interface Number Below");
		lblSelectInterfaceNumber.setBounds(363, 157, 242, 14);
		panel_2.add(lblSelectInterfaceNumber);
		lblSelectInterfaceNumber.setFont(new Font("Lucida Grande", Font.ITALIC, 11));
		
		//#####################################################################################
	    // Mitm Listner tables and controls for  Options tab
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Non HTTP Proxy Settings", TitledBorder.LEADING, TitledBorder.TOP, null, UIManager.getColor("CheckBoxMenuItem.selectionBackground")));
		panel_1.setBounds(6, 430, 1067, 220);
		Options.add(panel_1);
		panel_1.setLayout(null);

		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(6, 40, 1043, 67);
		panel_1.add(scrollPane_1);
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
							mtm.addEventListener(NonHttpUI.this);
							if(btnIntercept.getText().endsWith("ON"))
								mtm.setIntercept(true);
							
							if(isC2S.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_C2S);
							else if(isS2C.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_S2C);
							else if(isBoth.isSelected())
								mtm.setInterceptDir(mtm.INTERCEPT_BOTH);
							
							threads.put(mtm.ListenPort, mtm); /// track threads by the listening port
							Thread t = new Thread(mtm);
							t.start();
						}
					}else{ //delete a server thread
						int lPort = Integer.parseInt((String)tbm.getValueAt(rowid, 1));
						GenericMiTMServer mtm = ((GenericMiTMServer)threads.get(lPort));
						if(mtm != null){
							mtm.KillThreads();
							threads.remove(lPort);
						}
					}
				}


			}
		});
		ListTable.setModel(tbm);

		

		JLabel lblAddress = new JLabel("Server Address:");
		lblAddress.setBounds(272, 124, 107, 16);
		panel_1.add(lblAddress);
		SvrAddr = new JTextField();
		SvrAddr.setText("127.0.0.1");
		SvrAddr.setBounds(272, 144, 141, 28);
		panel_1.add(SvrAddr);
		SvrAddr.setColumns(10);

		JLabel lblPort = new JLabel("Listen Port:");
		
		lblPort.setBounds(519, 124, 127, 16);
		panel_1.add(lblPort);

		LstnPort = new JTextField();
		LstnPort.setText("1000");
		
		LstnPort.setBounds(519, 144, 75, 28);
		panel_1.add(LstnPort);
		LstnPort.setColumns(10);
		
		JLabel lblLstnPort = new JLabel("Server Port:");
		lblLstnPort.setBounds(424, 124,83, 16);
		panel_1.add(lblLstnPort);
		
		SvrPort = new JTextField();
		SvrPort.setText("1001");
		SvrPort.setBounds(425, 144, 75, 28);
		panel_1.add(SvrPort);
		SvrPort.setColumns(10);
		
		JLabel lblcertName = new JLabel("Certificate  HostName:");
		lblcertName.setBounds(103, 124,157, 16);
		panel_1.add(lblcertName);
		
		certName = new JTextField();
		certName.setText("www.example.com");
		certName.setBounds(103, 144, 157, 28);
		panel_1.add(certName);
		certName.setColumns(10);
		
		isSSL = new JCheckBox("SSL - (Export Burp's CACert as pkcs12 with  password 'changeit'. ");
		isSSL.setBounds(606, 118, 443, 28);
		panel_1.add(isSSL);
		
		/// Buttons for Clear History, export database, import database, add proxy, remove proxy
		JButton btnAdd = new JButton("Add");
		btnAdd.setBounds(16, 119, 75, 53);
		panel_1.add(btnAdd);
		btnAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				int lPort = Integer.parseInt(LstnPort.getText());
				if(threads.containsKey(lPort))
					Callbacks.printOutput("Listener Already Exits");
				else{
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
					
				}

			}
			
		});

		JButton btnClearHistory = new JButton("Clear History");
		btnClearHistory.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int rowCount=ntbm.getRowCount();

				for (int i=rowCount -1; i>=0; i--) {
					ntbm.log.remove(i);
					//ntbm.fireTableRowsDeleted(i, i);
				}
				LogEntry.clearTable();

			}
		});
		btnClearHistory.setBounds(932, 185, 117, 29);
		panel_1.add(btnClearHistory);

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
		btnRemoveProxy.setBounds(6, 185, 117, 29);
		panel_1.add(btnRemoveProxy);
		
		JButton btnSaveHistory = new JButton("Export History");
		btnSaveHistory.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String fs =  System.getProperty("file.separator");
				String file = System.getProperty("user.dir") + fs +"requests.sqlite";
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
		btnSaveHistory.setBounds(803, 185, 117, 29);
		panel_1.add(btnSaveHistory);
		
		JButton btnImportHistory = new JButton("Import History");
		btnImportHistory.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String fs =  System.getProperty("file.separator");
				String resultFile = System.getProperty("user.dir") + fs +"requests.sqlite";
				Frame fr = new Frame();
				FileDialog fd = new FileDialog(fr,"Import Database", FileDialog.LOAD);
				fd.setVisible(true);
				
				String imported = fd.getDirectory() +  fd.getFile();
				Path impPath = Paths.get(imported);
				Path localPath = Paths.get(resultFile);
				try {
					Files.copy(impPath, localPath, StandardCopyOption.REPLACE_EXISTING);
					//Delete The current table;
					int rowCount=ntbm.getRowCount();
					for (int i=rowCount -1; i>=0; i--) {
						ntbm.log.remove(i);
						//ntbm.fireTableRowsDeleted(i, i);
					}
					LinkedList<LogEntry> list = LogEntry.restoreDB();
					for(LogEntry le : list){
						ntbm.log.add(le);
					}
					
					
					
				} catch (IOException e1) {
					Callbacks.printError(e1.getMessage());
				}
				
			}
		});
		btnImportHistory.setBounds(674, 185, 117, 29);
		panel_1.add(btnImportHistory);
		
		JLabel lblNewLabel = new JLabel("Name the cert 'burpca.p12'  in Burp's installation folder)");
		lblNewLabel.setBounds(658, 144, 391, 16);
		panel_1.add(lblNewLabel);
		
		
		
		
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
		JPanel panel_4 = new JPanel();
		panel_4.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Match and Replace Rules", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_4.setBounds(564, 6, 509, 423);
		Options.add(panel_4);
		panel_4.setLayout(null);
		
		txtRules = new JTextArea();
		txtRules.setBounds(16, 47, 472, 358);
		panel_4.add(txtRules);
		txtRules.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				updateMatchRules();
				
			}
		});
		txtRules.setText(rules);
		
		errorMsg = new JLabel("");
		errorMsg.setBounds(16, 19, 472, 16);
		panel_4.add(errorMsg);
		errorMsg.setForeground(Color.RED);
		
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

		DNSRequests.setViewportView(DnsListTable);
		
		dnstTbm = (DefaultTableModel)DnsListTable.getModel();
		String DNSheader[] = new String[]{"Time","Domain","Client Address", "Client Name"};
		dnstTbm.setColumnIdentifiers(DNSheader);
		
	

		
		//#####################################################################################
		// Finalizing Setup functions
		
		
		if(AUTOSTART){
			btnStartDns.setText("Stop DNS");
			btnStartDns.setBackground(Color.GREEN);
			isDNSRunning = true;
			lblStatusDNS.setText("DNS ON");
		}
		if(this.getProperties("autostart","false").equals("true"))
			chckbxStartDnsOn.setSelected(true);
		else
			chckbxStartDnsOn.setSelected(false);
		
		// Update the network interface information
		updateInterfaceInformation();
		DNSIP = dnsIpTxt.getText();
		// order the tabs
		BurpTabs.addTab("Intercept", Intercept);
		BurpTabs.addTab("History", splitPane);
		BurpTabs.addTab("DNS Requests", null, DNSRequests, null);
		BurpTabs.add("Options", Options);
		// Add Tabs to main component
		add(BurpTabs);
		Callbacks.customizeUiComponent(BurpTabs);
		
		//Set DataUpdate Timer
		timer = new Timer();
		timer.scheduleAtFixedRate(new UpdateDBTask(queue,ntbm), 0, 2*1000);
	    //timer.schedule(new UpdateDBTask(queue,ntbm), 2 * 1000);
		
		


	}
//############################################################################################################################
// Supporting Functions
//############################################################################################################################
	private void updateMatchRules(){
	
		String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
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
		String fs =  System.getProperty("file.separator");
		String file = System.getProperty("user.dir") + fs + "nonHTTPmatch.txt";
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
			File f = new File(path + "/.dnsExtender/dns.properties");
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				File p = new File(path + "/.dnsExtender/dns.properties");
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
			File f = new File(path + "/.dnsExtender/dns.properties");
			if(f.exists()){
				config.load( new FileInputStream(f));
			}else{
				//config.load(ClassLoader.getSystemResourceAsStream("dns.properties"));
				File p = new File(path + "/.dnsExtender/dns.properties");
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
		lblStatusDNS.setText("DNS OFF");


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
	
	public synchronized void addEventListener(DNSConfigListener listener)	{
		_listeners.add(listener);
	}
	public synchronized void removeEventListener(DNSConfigListener listener)	{
		_listeners.remove(listener);
	}

	@SuppressWarnings("rawtypes")
	private synchronized void ToggleDNS(){
		Iterator i = _listeners.iterator();
		while(i.hasNext())	{
			((DNSConfigListener) i.next()).DNSToggle(null);
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
		queue.add(new LogEntry(evt.getData(),evt.getData(), evt.getSrcIP(), evt.getSrcPort(), evt.getDstIP(), evt.getDstPort(), evt.getDirection()));


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
					queue.add(new LogEntry(intbm.requestViewer.getMessage(), origReq, evt.getSrcIP(), evt.getSrcPort(), evt.getDstIP(), evt.getDstPort(), evt.getDirection()+" - Intercepted - Not Changed"));
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
	public JTextArea getTxtRules() {
		return txtRules;
	}
	
	public JTextField getTxtDNSPort() {
		return txtDNSPort;
	}
	public JLabel getLblSelected() {
		return lblSelected;
	}
}
