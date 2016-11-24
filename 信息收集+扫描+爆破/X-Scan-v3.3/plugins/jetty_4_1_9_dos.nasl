#
# Sarju Bhagat <sarju@westpoint.ltd.uk>
#
# GPLv2
#

# Changes by Tenable:
# - added CVE and OSVDB xrefs.
# - revised plugin title, changed family (6/17/09)


include("compat.inc");

if(description)
{
 script_id(17348);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-2381");
 script_bugtraq_id(9917);
 script_xref(name:"OSVDB", value:"4387");

 script_name(english:"Jetty < 4.2.19 HTTP Server HttpRequest.java Content-Length Handling Remote Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Jetty
that is older than 4.2.19.  The version is vulnerable to a unspecified
denial of service." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=224743" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.2.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


 script_summary(english:"Checks for the version of Jetty");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Westpoint Limited");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner || "Jetty/" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Jetty/4\.([01]\.|2\.([0-9][^0-9]|1[0-8]))", string:serv))
 {
   security_warning(port);
   exit(0);
 }
}
