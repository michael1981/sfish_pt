#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20319);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2931");
  script_bugtraq_id(15752);
  script_xref(name:"OSVDB", value:"21498");

  script_name(english:"Ipswitch Collaboration Suite / IMail SMTPD Multiple Commands Format String");
  script_summary(english:"Checks for format string vulnerability in Ipswitch Collaboration Suite / IMail SMTPD");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch Collaboration Suite or IMail
Server, commercial messaging and collaboration suites for Windows. 

The version of Ipswitch Collaboration Suite / IMail server installed
on the remote host contains an SMTP server that suffers from a format
string flaw.  By supplying a specially formatted argument to the
'EXPN', 'MAIL', 'MAIL FROM', or 'RCPT TO' commands, a remote attacker
may be able to corrupt memory on the affected host, crash the service,
or even execute arbitrary code remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=346&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics202.asp" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/imail_professional/im822.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch Collaboration Suite 2.02 / IMail 8.22 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_exclude_keys("SMTP/wrapped");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port) || get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Make sure the banner corresponds to ICS / IMail.
banner = get_smtp_banner(port:port);
pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
if (banner && egrep(pattern:pat, string:banner)) {
  # If safe checks are enabled, check the version in the banner.
  if (safe_checks()) {
    matches = egrep(pattern:pat, string:banner);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    if (ver == NULL) {
      exit(1, "cannot determine version of ICS / IMail SMTP service!");
    }
    else if (ver =~ "^([0-7]\.|8\.([01]\.|2[01]))") {
      security_hole(port);
      exit(0);
    }
  }
  # Else ...
  else {
    # Try several times to hang the daemon.
    tries = 2;
    for (iter=1; iter<=tries; iter++) {
      # Establish a connection.
      soc = smtp_open(port:port, helo:SCRIPT_NAME);
      if (soc) {
        c = "MAIL FROM: %s%s%s";
        send(socket:soc, data:string(c, "\r\n"));
        s = smtp_recv_line(socket:soc);

        # If we got a response, we're not vulnerable.
        if (strlen(s)) {
          smtp_close(socket:soc);
          exit(0);
        }
      }
    }

    # There's a problem if our exploit worked every time.
    if (iter > tries) {
      security_hole(port);
      exit(0);
    }
  }
}
