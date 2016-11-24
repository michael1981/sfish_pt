#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15404);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-2441");
 script_bugtraq_id(11300);
 script_xref(name:"OSVDB", value:"10504");

 script_name(english:"Kerio MailServer < 6.0.3 Unspecified Vulnerability");
 script_summary(english:"Checks for Kerio MailServer < 6.0.3");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote mail server has an unspecified vulnerability."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is running a version of Kerio MailServer prior to
6.0.3. 

There is an undisclosed flaw in the remote version of this server that
might allow an attacker to execute arbitrary code on the remote host."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.kerio.com/mailserver/history"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Kerio MailServer 6.0.3 or newer."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2004/09/30"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2004/09/30"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/10/01"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;
banner = get_smtp_banner(port:port);
if ( ! banner) exit(0);
if (egrep(string:banner, pattern:"^220 .* Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.[0-2]) ESMTP ready") )
	{
		security_hole(port);
		exit(0);
	}
