#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# June 4, 2002 Revision 1.9 Additional information and refrence information
# added by Michael Scheidell SECNAP Network Security, LLC June 4, 2002
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)


include("compat.inc");

if(description)
{
 script_id(10767);
 script_version ("$Revision: 1.18 $");

 script_name(english:"Nimda Worm Infected HTML File Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"Your server appears to have been compromised by the Nimda mass mailing 
worm. It uses various known IIS vulnerabilities to compromise the 
server.

Anyone visiting compromised Web servers will be prompted to download an 
.eml (Outlook Express) email file, which contains the worm as an 
attachment. 

In addition, the worm will create open network shares on the infected 
computer, allowing access to the system. During this process
the worm creates the guest account with Administrator privileges.

Note: This plugin looks for the presence of the string 'readme.eml' 
on the remote web server and may result in false positives." );
 script_set_attribute(attribute:"solution", value:
"Take this server offline immediately, rebuild it and apply ALL vendor 
patches and security updates before reconnecting it to the Internet, 
as well as security settings discussed in Additional Information section
of Microsoft's web site at

http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx

Check ALL of your local Microsoft based workstations for infection.
Note: this worm has already infected more than 500,000 computers 
worldwide since its release in late 2001." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2001-26.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Tests for Nimda Worm infected HTML files");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check for references to readme.eml in default HTML page..

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 r = http_get_cache(item:"/", port:port);
 if(r && "readme.eml" >< r)	
 	security_hole(port);
}
