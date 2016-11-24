#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE


include("compat.inc");

if(description)
{
 script_id(10604);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-1050");
 script_bugtraq_id(1830);
 script_xref(name:"OSVDB", value:"500");

 script_name(english:"Allaire JRun Crafted Request WEB-INF Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Requesting a URL with '/./' prepended to it
makes the remote Allaire Server display the content of 
a remote directory, instead of its index.html file.

An attacker may use this flaw to download 'hidden' files on 
your server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JRun 3.0sp2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Make a request like http://www.example.com/./WEB-INF");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if(get_port_state(port))
{
  req = http_get(item:"/./WEB-INF/", port:port);
  r =   http_keepalive_send_recv(port:port, data:req);
  if(ereg(pattern:"^HTTP.* 200 ", string:r)  )
  {
   if("Index of /./WEB-INF/" >< r)security_warning(port);
  }
}
