#
# (C) Tenable Network Security, Inc.
#

# Some information:
# http://www.cl.cam.ac.uk/research/dtg/attarchive/vnc/protocol.html
# http://www.cl.cam.ac.uk/research/dtg/attarchive/vnc/rfbproto.pdf
# http://www.realvnc.com/docs/rfbproto.pdf



include("compat.inc");

if(description)
{
 script_id(19288);
 script_version ("$Revision: 1.20 $");
 script_name(english: "VNC Server Security Type Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A VNC server is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"This script checks the remote VNC server protocol version and the
available 'security types'." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 script_summary(english: "Identifies the RFB protocol version (VNC) & security types");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("vnc.nasl");
 script_require_ports("Services/vnc", 5900);
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');


function connection_refused(port, socket)
{
 local_var reason, r, l, report;

 reason = '';

 r = recv(socket: socket, min: 4, length: 4);
 if (strlen(r) == 4)
 {
   l = ntohl(n: r);
   reason = recv(socket: socket, length: l);
 }
 report = '\nThe remote VNC server rejected the connection.\n';

 if (strlen(reason) > 0)
   report += 'Reason : ' + reason;
 else
   report += 'Nessus could not determine why.';

 security_note(port:port, extra:report);
 if (COMMAND_LINE) display(report);
}

port = get_kb_item("Services/vnc");
if (! port) port = 5900;	# or 5901, 5902...?

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if(! s) exit(0);

r = recv(socket: s, length: 512, min: 12);
if (strlen(r) < 12) exit(0);

v = eregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v)) exit(0);

major = int(v[1]);
minor = int(v[2]);

debug_print('RFB protocol version = ', major, '.', minor, '\n');

set_kb_item(name: 'RFB/version/'+port, value: strcat(major, '.', minor));

if (major < 3)
  exit(0);

# Send back the same protocol
send(socket: s, data: r);

# Security types names
rfb_sec = make_array(
 -6, "MS Logon (UltraVNC)",
 0, "Invalid (connection refused)", 
 1, "None", 
 2, "VNC authentication",
 5, "RA2", 
 6, "RA2ne", 
 16, "Tight", 
 17, "Ultra", 
 18, "TLS",
 19, "VeNCrypt"
);

if (major == 3 && minor >= 3 && minor < 7)
{
 r = recv(socket: s, min: 4, length: 4);
 if (strlen(r) != 4)
   exit(0);

 st = ntohl(n: r);
 if (st == 0)
 {
  connection_refused(port: port, socket: s);
 }
 else
 {
  set_kb_item(name: 'VNC/SecurityType/'+port, value: st);
  report = strcat('The remote VNC server chose security type #', st);
  if (rfb_sec[st])
    report = strcat(report, ' (', rfb_sec[st], ')');

  if (st == 1)
    set_kb_item(name: 'VNC/SecurityNoAuthentication', value:port);

   report = string("\n",report);

   security_note(port: port, extra: report);
   if (COMMAND_LINE) display(report);
 }
}
else if (major > 3 || minor >= 7)
{
 r = recv(socket: s, min: 1, length: 1);
 if (strlen(r) < 1)
   exit(0);

 n = ord(r);
 if (n == 0)	# rejected connection
 {
  connection_refused(port: port, socket: s);
 }
 else
 {
  report = '';
  for (i = 0; i < n; i ++)
  {
   r = recv(socket: s, min: 1, length: 1);
   if (strlen(r) < 1)
     break;

   st = ord(r);
   if (rfb_sec[st])
    report = strcat(report, '+ ', st, ' (', rfb_sec[st], ')\n'); 
   else
    report = strcat(report, '+ ', st, '\n');
   if (st == 1)
    set_kb_item(name: 'VNC/SecurityNoAuthentication', value:port);
  }

  if (report)
  { 
   if (max_index(split(report)) > 1) s = "s";
   else s = "";

   report = string (
     "\n",
     "The remote VNC server supports the following security type", s, " :\n",
    "\n",
     report
   );

   security_note(port: port, extra: report);
   if (COMMAND_LINE) display(report);
  }
 }
}
else
  exit(0);

if (service_is_unknown(port: port))
  register_service(port: port, proto: 'vnc');
