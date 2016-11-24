#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19236);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-1873", "CVE-2006-6558");
  script_bugtraq_id(13847, 13848);
  script_xref(name:"OSVDB", value:"17054");
  script_xref(name:"OSVDB", value:"17055");
  script_xref(name:"OSVDB", value:"32264");

  script_name(english:"Crob FTP Server < 3.6.1 build 263 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to multiple buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Crob FTP Server on the remote host suffers from
multiple remote buffer overflows.  Once authenticated, an attacker can
exploit these vulnerabilities to crash the affected daemon and even
execute arbitrary code remotely within the context of the affected
service." );
 script_set_attribute(attribute:"see_also", value:"http://security.lss.hr/en/index.php?page=details&ID=LSS-2005-06-06" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2926" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Crob FTP Server version 3.6.1 build 263 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 
  script_summary(english:"Checks for multiple buffer overflow vulnerabilities in Crob FTP Server");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Check for the vulnerability.
if (safe_checks()) {
  s = get_ftp_banner(port:port);
  if (!s) exit(0);
  if (
    egrep(string:s, pattern:"^220-Crob FTP Server V([0-2][^0-9]|3\.([0-5][^0-9]|6\.0))") ||
    (
      report_paranoia > 1 &&
      egrep(string:s, pattern:"^220-Crob FTP Server V3\.6\.1")
    )
  ) {
    w = 
"Nessus has determined the vulnerability exists on the remote host 
simply by looking at the version of Crob FTP Server installed there.
If the version is 3.6.1 and the build is 263 or later, consider this a
false positive.";
    security_warning(port:port, extra: w);
  }
 exit(0);
}
else {
  s = get_ftp_banner(port:port);
  if (!s || ("Crob FTP Server" >!< s)) exit(0);

 # nb: we need to log in to exploit the vulnerability.
 user = get_kb_item("ftp/login");
 pass = get_kb_item("ftp/password");
 if (!user || !pass) {
  exit(1, "ftp/login and/or ftp/password are empty");
 }

 # Open a connection.
 soc = open_sock_tcp(port);
 if (!soc) exit(1);
 s = recv_line(socket:soc, length:1024);
 if (!strlen(s)) exit(1);


  if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
    close(soc);
    exit(1, "cannot login with supplied FTP credentials");
  }

  # Try to crash the service.
  buf = crap(4100);
  c = raw_string("STOR ", buf);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);

  c = string("RMD ", buf);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);

  soc2 = open_sock_tcp(port);
  if (soc2) {
    if (!ftp_authenticate(socket:soc2, user:user, pass:pass)) {
      security_warning(port);
    }
    ftp_close(socket:soc2);
  }

  ftp_close(socket:soc);
}
