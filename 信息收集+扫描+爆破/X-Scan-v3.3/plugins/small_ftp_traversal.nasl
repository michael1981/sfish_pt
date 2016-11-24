#
# (C) Tenable Network Security, Inc.
#

# This is a generic test which checks for FTP traversal vulns.
#
# This affects SmallFTPd and possibly other servers
# See http://marc.info/?l=vuln-dev&m=105171837001921&w=2

include( 'compat.inc' );

if(description)
{
  script_id(11573);
  script_bugtraq_id(7472, 7473, 7474);
  script_xref(name:"OSVDB", value:"51746");
  script_xref(name:"OSVDB", value:"51747");
  script_xref(name:"OSVDB", value:"51748");
  script_version ("$Revision: 1.10 $");

  script_name(english:"smallftpd Multiple Vulnerabilities (Traversal, DoS)");
  script_summary(english:"Attempts to break out of the FTP root");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote FTP service is vulnerable to an access control breach."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote FTP server is vulnerable to a flaw which allows users
to access files which are outside the FTP server root.

An attacker may break out of his FTP jail by issuing the command :

	CWD \..\..

In addition, it has been reported that a user can crash the
service by supplying malformed input to the login process
or large arguments to several commands."
  );

  script_set_attribute(
    attribute:'solution',
    value:"If you are running smallftpd upgrade to version 1.0.3 or higher,
otherwise contact your vendor for a patch"
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://archives.neohapsis.com/archives/vuln-dev/2003-q2/0063.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"FTP");
  script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


function dir()
{
 local_var ls, p, r, result, soc2;
 global_var soc;

 p = ftp_pasv(socket:soc);
 if(!p)exit(0);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(!soc2)return(0);
 ls = string("LIST .\r\n");
 send(socket:soc, data:ls);
 r = ftp_recv_line(socket:soc);
 if(egrep(pattern:"^150 ", string:r))
 {
  result = ftp_recv_listing(socket:soc2);
  close(soc2);
  r = ftp_recv_line(socket:soc);
  return(result);
 }
 return(0);
}


#
# The script code starts here
#


soc = open_sock_tcp(port);
if(soc)
{
 login = get_kb_item("ftp/login");
 pass = get_kb_item("ftp/password");
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
 send(socket:soc, data:string("CWD /\r\n"));
 r = ftp_recv_line(socket:soc);
 listing1 = dir();
 if(!listing1)exit(0);

 send(socket:soc, data:string("CWD \\..\\..\r\n"));
 r = ftp_recv_line(socket:soc);
 listing2 = dir();
 if(!listing2)exit(0);

 close(soc);

 if(listing1 != listing2)security_hole(port);
 }
}
