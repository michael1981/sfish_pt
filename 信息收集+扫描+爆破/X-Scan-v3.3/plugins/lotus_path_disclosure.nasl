#
# (C) Tenable Network Security, Inc.
#

# based on php3_path_disclosure by Matt Moore
#
# References
# From: "Peter_Grundl" <pgrundl@kpmg.dk>
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002006: Lotus Domino Physical Path Revealed
# Date: Tue, 2 Apr 2002 16:18:06 +0200
#


include("compat.inc");

if(description)
{
 script_id(11009);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0245", "CVE-2002-0408");
 script_bugtraq_id(4049);
 script_xref(name:"OSVDB", value:"828");
 script_xref(name:"OSVDB", value:"15453");

 script_name(english:"IBM Lotus Domino Banner Nonexistent .pl File Request Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be Lotus Domino HTTP service. The
installed version contains a flaw which allows an attacker to 
determine the physical path to the web root by requesting a
nonexistent '.pl' file." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-02/0039.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-04/0003.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-04/0029.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Domino 5.0.10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Tests for Lotus Physical Path Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");
port = get_http_port(default:80);

if(get_port_state(port))
{ 
 file = string("/cgi-bin/com5.pl");
 res = http_send_recv3(method:"GET", item:"/cgi-bin/com5.pl", port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");

 if(egrep(pattern:"[^A-Z][A-Za-z]:.*com5\.pl", string:res[2], icase:TRUE))
   security_warning(port);
}
