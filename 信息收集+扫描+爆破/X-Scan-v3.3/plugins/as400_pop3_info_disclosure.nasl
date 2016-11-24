#
# (C) Tenable Network Security
#
# 


include("compat.inc");

if (description) {
  script_id(18046);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1133");
  script_bugtraq_id(13156);
  script_xref(name:"OSVDB", value:"15510");

  script_name(english:"IBM AS400 and iSeries POP3 Server Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote POP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the POP3 service that comes with
all modern AS/400 and iSeries servers.  Further, this service is prone
to an information disclosure vulnerability due to the responses it
provides to username / password combinations.  This allows a remote
attacker to determine valid user profiles.  Further, the service
offers a means of brute forcing passwords since it does not block a
connection or disable a user after a given number of invalid login
attempts." );
 script_set_attribute(attribute:"see_also", value:"http://www.venera.com/downloads/Enumeration_of_AS400_users_via_pop3.pdf" );
 script_set_attribute(attribute:"solution", value:
"Disable the POP3 service if not needed." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for remote information disclosure vulnerability in IBM AS400 and iSeries POP3 server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");

  exit(0);
}


include("pop3_func.inc");

if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);

banner = get_pop3_banner(port:port);
if ( ! banner || "+OK POP3 server ready" >!< banner ) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s) || "+OK POP3 server ready" >!< s ) {
  close(soc);
  exit(0);
}
s = chomp(s);


# Try various ways to log in.
i=-1;
# - real account.
users[++i] = "qsysopr";
result[i] = "ERR .+ CPF22E2";
# - bogus user; eg, "030757"
now = split(gettimeofday(), sep:".", keep:0);
users[++i] = now[1];
result[i] = "ERR .+ CPF2204";
# - real account but w/o password
users[++i] = "qspl";
result[i] = "ERR .+ CPF22E5";

matches = 0;
foreach i (keys(users)) {
  c = string("USER ", i);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
  if (resp && "OK" >< resp) {
    c = string("PASS nessus");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        if (egrep(string:s, pattern:result[i])) ++matches;
        break;
      }
      resp = "";
    }
  }
}


# If the result of each login attempt matched the expected pattern,
# there's a problem.
if (matches == i) security_warning(port);


# Logout.
c = "QUIT";
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
