#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#


include("compat.inc");

if(description)
{
 script_id(10844);
 script_cve_id("CVE-2003-0223");
 script_bugtraq_id(7731);
 script_xref(name:"OSVDB", value:"7737");
 script_version ("$Revision: 1.25 $");
 script_name(english:"Microsoft IIS ASP Redirection Function XSS");

 script_set_attribute(attribute:"synopsis", value:
"ASP.NET is affected by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote ASP.NET installation is vulnerable to a cross-site 
scripting issue.

An attacker may exploit this flaw to execute arbitrary HTML code 
on third-party clients." );
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/254001" );
 script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/en-us/library/ms972823.aspx" );
 script_set_attribute(attribute:"solution", value:
"Microsoft released a patch for this issue :

http://support.microsoft.com/?kbid=811114" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();


 summary["english"] = "Tests for ASP.NET CSS";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

str = "/~/<script>alert(document.cookie)</script>.aspx?aspxerrorpath=null";
r = http_send_recv3(port: port, method: 'GET', item: str);
if (isnull(r)) exit(0);
lookfor = "<script>alert(document.cookie)</script>";
if (lookfor >< r[2])
{
   	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
