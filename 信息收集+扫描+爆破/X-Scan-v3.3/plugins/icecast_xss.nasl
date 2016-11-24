#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref:  Markus Wörle
#
# This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/22/2009)


include("compat.inc");

if(description)
{
 script_id(14390);
 script_bugtraq_id(11021);
 script_cve_id("CVE-2004-0781");
 script_xref(name:"OSVDB", value:"9143");
 script_xref(name:"Secunia", value:"12344");
 script_xref(name:"Secunia", value:"12361");
 script_version ("$Revision: 1.10 $");
 
 script_name(english:"Icecast list.cgi User-Agent XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming media server is hosting a CGI script that is 
affected by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast which is as old as or 
older than version 1.3.12.

This version is affected by a cross-site scripting vulnerability
in the status display functionality. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

As a result of this vulnerability, it is possible for a remote 
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication 
credentials as well as other attacks." );
 script_set_attribute(attribute:"solution", value:
"Debian has releasted a patch for the debian based Icecast package." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
 summary["english"] = "check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner &&
   egrep(pattern:"icecast/1\.3\.([0-9]|1[0-2])[^0-9]", string:banner))
{
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

