#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(17594);
  script_version ("$Revision: 1.4 $");
  script_bugtraq_id(12866);
  script_cve_id( "CVE-2005-0845" );

  script_name(english:"NetWin SurgeMail Multiple Remote Unspecified Vulnerabilities");
  script_summary(english:"Checks the version of the remote NetWin server");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to multiple conditions.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running NetWin SurgeMail, a mail server
application. 

The remote version of this software is affected by multiple
unspecified vulnerabilities which have been disclosed by the vendor."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to NetWin SurgeMail 3.0.0c2 or newer"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/394055'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_family(english:"SMTP problems");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);

if ( ! banner ) exit(0);

if ( egrep(string:banner, pattern:"^220.* SurgeSMTP \(Version ([0-2]\.|3\.0[ab]|3\.0c[01][^0-9])")) security_hole(port);
