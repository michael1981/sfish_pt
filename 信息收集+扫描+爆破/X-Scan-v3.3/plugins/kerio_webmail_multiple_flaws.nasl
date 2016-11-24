#
# (C) Tenable Network Security, Inc.
#

# Modified by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref 1:
#  Date: Wed, 18 Jun 2003 21:58:51 +0200 (CEST)
#  Subject: Multiple buffer overflows and XSS in Kerio MailServer
#  From: "David F.Madrid" <conde0@telefonica.net>
#  To: <bugtraq@securityfocus.com>
# Ref 2:
#  Abraham Lincoln" <sunninja@scientist.com>
#
# This script is released under the GNU GPL v2


include("compat.inc");

if(description)
{
 script_id(11763);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2002-1434", "CVE-2003-0487", "CVE-2003-0488");
 script_bugtraq_id(5507, 7966, 7967, 7968, 8230, 9975);
 script_xref(name:"OSVDB", value:"2159");
 script_xref(name:"OSVDB", value:"4953");
 script_xref(name:"OSVDB", value:"4954");
 script_xref(name:"OSVDB", value:"4955");
 script_xref(name:"OSVDB", value:"4956");
 script_xref(name:"OSVDB", value:"4958");

 script_name(english:"Kerio WebMail < 5.7.7 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running version 5 of the Kerio MailServer.

There are multiple flaws in this interface which may allow
an attacker with a valid webmail account on this host 
to obtain a shell on this host or to perform
a cross-site-scripting attack against this host
with version prior to 5.6.4.

Version of MailServer prior to 5.6.5 are also prone to a 
enial of service condition when an incorrect login to the
admin console occurs. This could cause the server to crash.

Version of MailServer prior to 5.7.7 is prone to a remotely 
exploitable buffer overrun condition.
This vulnerability exists in the spam filter component. 
If successfully exploited, this could permit remote attackers 
to execute arbitrary code in the context of the MailServer software. 
This could also cause a denial of service in the server.

*** This might be a false positive, as Nessus did not have
*** the proper credentials to determine if the remote Kerio
*** is affected by this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 5.7.7 or newer" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 script_summary(english:"Checks for Kerio MailServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security & David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

res = http_get_cache(item:"/", port:port);
if (egrep(string:res, pattern:"^Server: Kerio MailServer ([0-4]\.|5\.[0-6]\.|5\.7\.[0-6])") )	
{
 		security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
