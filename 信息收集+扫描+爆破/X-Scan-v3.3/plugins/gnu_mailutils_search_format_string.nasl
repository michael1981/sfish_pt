#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19605);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2878");
  script_bugtraq_id(14794);
  script_xref(name:"OSVDB", value:"19306");

  name["english"] = "GNU Mailutils imap4d Search Command Format String Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"GNU Mailutils is a collection of mail utilities, including an IMAP4
daemon, a POP3 daemon, and a very simple mail client. 

The remote host is running a version of GNU Mailutils containing a
format string vulnerability in its IMAP4 daemon.  By exploiting these
issues, a remote attacker may be able to execute code remotely in the
context of the user executing the daemon process, typically root." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=303&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://savannah.gnu.org/patch/index.php?func=detailitem&item_id=4407" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for search command format string vulnerability in GNU Mailutils imap4d";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


# Check the IMAP daemon.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (get_port_state(port) && !get_kb_item("imap/false_imap")) {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");

  if ((user == "") || (pass == "")) {
    exit(0, "imap/login and/or imap/password are empty");
  }

  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Read banner and make sure it looks like GNU Mailutils.
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s) || "* OK IMAP4rev1" >!< s) {
    close(soc);
    exit(0);
  }

  # Log in.
  ++tag;
  c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
  if (!resp) exit(0);
  else if (resp =~ "NO") {
    exit(1, "couldn't login with supplied IMAP credentials");
  }

  # Select a mailbox (needed for search command).
  ++tag;
  c = string("nessus", string(tag), " SELECT INBOX");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
  if (!resp || resp =~ "NO") exit(0);

  # Try to exploit the flaw.
  ++tag;
  c = string("nessus", string(tag), " SEARCH TOPIC %.8X");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # Check the response. A vulnerable version should report something like "BAD 
  # SEARCH Unknown search criterion (near 00000040)" -- "00000040" is the 
  # interpreted value of "%.8x" (ie, print 8 hex chars of the stack 
  # first value) -- and "BAD SEARCH Unknown search criterion (near %.8X)" 
  # for a patched version.
  if (s && egrep(pattern:"Unknown search criterion \(near [0-9A-F]{8}\)", string:s)) {
    security_warning(port);
  }

  # Be nice and logout if there's a connection.
  if (soc) {
    ++tag;
    c = string("a", string(tag), " LOGOUT");
    send(socket:soc, data:string(c, "\r\n"));
    close(soc);
  }
}
