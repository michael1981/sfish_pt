#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11933);
 script_version ("$Revision: 1.64 $");
 script_name(english:"Do not scan printers");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a printer and will not be scanned." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a network printer or multi-function
device.  Such devices often react very poorly when scanned - some
crash, others print a number of pages.  To avoid problems, Nessus has
marked the remote host as 'Dead' and will not scan it." );
 script_set_attribute(attribute:"solution", value:
"If you are not concerned about such behavior, enable the 'Scan Network
Printers' setting under the 'Do not scan fragile devices' advanced
settings block and re-run the scan." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


 script_summary(english:"Exclude AppSocket & socketAPI printers from scan");
 script_category(ACT_SETTINGS);

# script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"no");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Settings");
# Or maybe a "scan option" family?
 script_dependencie("dont_scan_settings.nasl");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("telnet_func.inc");
# We have to keep the old HTTP API
include("http_func.inc");
include("snmp_func.inc");

global_var tcp_sockets;
if ( islocalhost() ) exit(0);

function init_tcp()
{
 local_var i;
 local_var soc;
 local_var limit;
 local_var flag;
 local_var keys;

 if ( NASL_LEVEL >= 3005 )
 {
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
 {
  if ( ! get_port_state(_FCT_ANON_ARGS[i]) ) continue;
  soc = open_sock_tcp(_FCT_ANON_ARGS[i], nonblocking:TRUE);
  if ( soc ) tcp_sockets[_FCT_ANON_ARGS[i]] = soc;
 }

 limit = unixtime() + get_read_timeout();
 keys = keys(tcp_sockets);
 while ( unixtime() < limit )
 {
  for ( i = 0 ; i < max_index(keys) ; i ++ )
  {
   if ( ! socket_ready(tcp_sockets[keys[i]]) ) flag ++;
  }
  if ( flag == 0 ) break;
  usleep(5000);
 }

  for ( i = 0 ; i < max_index(keys) ; i ++ )
  {
   if ( socket_ready(tcp_sockets[keys[i]]) <= 0 || socket_get_error(tcp_sockets[keys[i]]) != NOERR ) { 
	close(tcp_sockets[keys[i]]); 
	tcp_sockets[keys[i]] = NULL; 
   }
  }
 }
 else 
 {
  # Nessus 2.x 
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
  tcp_sockets[keys[i]] = open_sock_tcp(_FCT_ANON_ARGS[i]);
 }
}

if ( get_kb_item("Scan/Do_Scan_Printers" ) ) exit(0);
i = 0;
printers[i++] = "JETDIRECT";
printers[i++] = "HP ETHERNET MULTI-ENVIRONMENT";
printers[i++] = "OKI OkiLAN";
printers[i++] = "LaserJet";
printers[i++] = "Xerox";
printers[i++] = "Canon iR";
printers[i++] = "Canon LBP";
printers[i++] = "Lantronix MSS100";
printers[i++] = "Generic 30C-1";
printers[i++] = "Network Printer";
printers[i++] = "Brother NC";
printers[i++] = "FAST-KYO-TX";
printers[i++] = "KYOCERA Printer";
printers[i++] = "Lexmark";
printers[i++] = "Fiery";
printers[i++] = "TOSHIBA e-STUDIO";
printers[i++] = "Dell Laser Printer";
printers[i++] = "Dell Color Laser Printer";
printers[i++] = "RICOH Network Printer";
printers[i++] = "Konica IP Controller";
printers[i++] = "IBM Infoprint";
printers[i++] = "TGNet PSIO";
printers[i++] = "XEROX";
printers[i++] = "NetQue";
printers[i++] = "WorkCentre Pro";
printers[i++] = "SHARP AR-M620N";

i = 0;

oids[i++] = "1.3.6.1.2.1.1.1.0";
oids[i++] = "1.3.6.1.2.1.1.4.0";


if ( get_kb_item("SNMP/community") )
{
 port = get_kb_item("SNMP/port"); 
 community = get_kb_item("SNMP/community");
 soc = open_sock_udp (port);
 if (  soc ) 
 {
  foreach oid ( oids )
  {
  desc = snmp_request(socket:soc, community:community, oid:oid);
  if ( desc )
  { 
   foreach printer (printers)
   {
     if ( printer >< desc ) 
     {
      set_kb_item(name: "Host/dead", value: TRUE);
      security_note(port: 0, extra:'\nSNMP reports it as ' + printer + '.\n');
      exit(0);
     }
    }
   }
  }
  close(soc);
 }
}



# First try UDP AppSocket

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);
  if ( soc )
  {
  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('UDP AppSocket on port ', port, '\n');
    security_note(port: 0, extra:'\nUDP AppSocket on port ' + port + '.\n');
    exit(0);
   }
  }
}

init_tcp(21, 23, 2002, 9200, 79, 80, 280, 631, 7627);



port = 21;
if( tcp_sockets[port] )
{
 soc = tcp_sockets[port];
 banner = recv_line(socket:soc, length:4096);
 if("JD FTP Server Ready" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('JD FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nJD FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ("220 Dell Laser Printer " >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( banner =~ "^220 Dell .* Laser" )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 DPO-[0-9]+ FTP Server", string:banner) )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Toshiba Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nToshiba Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 .* Lexmark.* FTP Server", string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Lexmark Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nLexmark Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 LANIER .* FTP server", string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('LANIER Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nLANIER Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ("220 Print Server Ready." >< banner)
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0, extra:'\nGeneric printer FTP server on port ' + port + '.\n');
  exit(0);
 }
}

port = 23;
if( tcp_sockets[port] )
{
 soc = tcp_sockets[port];
 banner = telnet_negotiate(socket:soc);
 if("HP JetDirect" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP JetDirect telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nHP JetDirect telnet server on port ' + port + '.\n');
    exit(0);
 }
 if("RICOH Maintenance Shell" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('RICOH Printer telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nRICOH Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if ("Copyright (C) 2001-2002 KYOCERA MITA CORPORATION" >< banner )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Kyocera Printer telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nKyocera Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if ("LANIER Maintenance Shell" >< banner )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('LANIER telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nLANIER Printer telnet server on port ' + port + '.\n');
    exit(0);
 }

}


# Xerox DocuPrint
port = 2002;
if ( get_port_state(port) )
{
 soc = tcp_sockets[port];
 if ( soc )
 {
  banner = recv(socket:soc, length:23);
  if ( banner && 'Please enter a password' >< banner ) {
    	set_kb_item(name: "Host/dead", value: TRUE);
    	security_note(port: 0, extra:'\nXerox DocuPrint service on port ' + port + '.\n');
	exit(0);
	}
 }
}

# Dell laser printers (5310n at least).
port = 9200;
if (get_port_state(port))
{
  soc = tcp_sockets[port];
  if (soc)
  {
    banner = recv(socket:soc, length:48, min:31);

    if (banner && stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "Dell Laser Printer ")) == 1)
    {
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nDell Laser Printer service on port ' + port + '.\n');
      exit(0);
    }
  }
}

# Lexmark Optra returns on finger port:
# Parallel port 1
# Printer Type: Lexmark Optra LaserPrinter
# Print Job Status: No Job Currently Active
# Printer Status: 0 Ready

port = 79;
if (get_port_state(port))
{
 soc = tcp_sockets[port];
 if (soc)
 {
   banner = recv(socket:soc, length: 512);
   if (strlen(banner) == 0)
   {
    send(socket: soc, data: 'HELP\r\n');
    banner = recv(socket:soc, length: 512);
   }
   if (banner && 'Printer type:' >< banner)
   {
     set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0, extra:'\nProbable Lexmark Optra LaserPrinter service on port ' + port + '.\n');
     exit(0);
   }
  }
}


# Patch by Laurent Facq
ports = make_list(80, 280, 631, 7627);
foreach port (ports)
{
 if(get_port_state(port))
 {
  soc = tcp_sockets[port];
  if ( !soc ) continue;
  send(socket:soc, data:string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n"));
  banner = http_recv(socket:soc);

  if(
    "Dell Laser Printer " >< banner ||
    (
      "Server: EWS-NIC4/" >< banner &&
      "Dell MFP Laser" >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell printer-related web server on port '+ port + '.\n');
    exit(0);
  }
  else if ( 
    ("<title>Hewlett Packard</title>" >< banner) || (egrep(pattern:"<title>.*LaserJet.*</title>", string:banner, icase:TRUE)) || ("SERVER: HP-ChaiSOE/" >< banner)  ||
    (
      "Server: Virata-EmWeb/" >< banner && 
      "<title> HP Color LaserJet " >< banner
    ) ||
    (
      "Server: HP-ChaiSOE/" >< banner && 
      "/hp/device/this.LCDispatcher" >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer-related web server on port '+ port+ '.\n');
    exit(0);
  }
  else if ( 
    banner && 
    (
      "Server: Xerox_MicroServer/Xerox" >< banner ||
      ("Server: Webserver" >< banner && "XEROX WORKCENTRE" >< banner) ||
      "Fuji Xerox Co., Ltd. All Rights Reserved. -->" >< banner
    )
  )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Xerox web server on port ', port, '\n');
    security_note(port: 0, extra:'\nXerox web server on port ' + port + '.\n');
    exit(0);
  }
  else if ( banner && ("Server: Rapid Logic/" >< banner ||
                       ("Server: Virata-EmWeb" >< banner && report_paranoia > 1) ) )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP printer: Rapid-Logic / Virata-EmWeb on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer: Rapid-Logic / Virata-EmWeb on port ' + port + '.\n');
    exit(0);
  }
 else if(banner && "Fiery" >< banner )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Fiery WebTools on port ', port, '\n');
    security_note(port: 0, extra:'\nFiery WebTools on port ' + port + '.\n');
    exit(0);
  }
  else if (banner && "Server: Web-Server/" >< banner)
  {
   if (
    (
     "<title>Web Image Monitor" >< banner &&
     'location.href="/web/guest/en/websys/webArch/mainFrame.cgi' >< banner
    ) ||
    (
     '<FRAME SRC="/en/top_head.cgi" NAME="header"' >< banner &&
     '<FRAME SRC="/en/top_main.cgi" NAME="mainmenu"' >< banner
    )
   )
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('RICOH web server on port ', port, '\n');
    security_note(port: 0, extra:'\nRicoh web server on port ' + port + '.\n');
    exit(0);
   }
  }
 }
}


# open ports?
ports = get_kb_list("Ports/tcp/*");
# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4990.html
appsocket = 0;


foreach p (keys(ports))
{
  p = int(p - "Ports/tcp/");
  if (	   p == 35		# AppSocket for QMS
	|| p == 2000		# Xerox
	|| p == 2501		# AppSocket for Xerox
	|| (p >= 3001 && p <= 3005)	# Lantronix - several ports
	|| (p >= 9100 && p <= 9300)	# AppSocket - several ports
#        || p == 10000 		# Lexmark
	|| p == 10001)		# Xerox - programmable :-(
    appsocket = 1;
# Look for common non-printer ports
	 else if (
          p != 21              # FTP
       && p != 23              # telnet
       && p != 79
       && p != 80              # www
       && p != 139 && p!= 445  # SMB
       && p != 280             # http-mgmt
       && p != 443
       && p != 515             # lpd
       && p != 631 	       # IPP
       && p != 8000 
       && p != 10002
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers    
	exit(0);

}


# OK, this might well be an AppSocket printer
if (appsocket)
{
  security_note(port:0, extra:'\nThe remote host seems to be an AppSocket printer');
  debug_print('Looks like an AppSocket printer\n');
  set_kb_item(name: "Host/dead", value: TRUE);
}
