#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20976);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-0928");
  script_bugtraq_id(16808);
  script_xref(name:"OSVDB", value:"23475");

  script_name(english:"ArGoSoft Mail Server _DUMP Command System Information Disclosure");
  script_summary(english:"Checks for _DUMP command information disclosure vulnerability in ArGoSoft POP3 server");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is subject to an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft Mail Server, a messaging system
for Windows. 

An unauthenticated attacker can gain information about the installed
application as well as the remote host itself by sending the '_DUMP'
command to the POP3 server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-02/0438.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/mailserver/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server 1.8.8.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");

  exit(0);
}


include("global_settings.inc");
include("pop3_func.inc");


if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure the banner is from ArGoSoft.
banner = get_pop3_banner(port:port);
if (!banner || "+OK ArGoSoft Mail Server" >!< banner) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);


# Try to exploit the flaw.
c = string("_DUMP");
send(socket:soc, data:string(c, "\r\n"));
n = 0;
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s);
  if (!isnull(m)) {
    resp = m[1];
    if ("-ERR" >< resp) break;
  }
  else if (s == ".") break;
  else info += s + '\n';
  n ++;
  if ( n > 200 ) break;
}


# There's a problem if we got a response.
if (info) {
  if (report_verbosity > 1)
    security_warning(port:port, extra: info);
  else
    security_warning(port:port);
}


# Clean up.
close(soc);
