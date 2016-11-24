#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
	script_id(12203);
	script_version("$Revision: 1.11 $");
	script_cve_id("CVE-2004-1920");
	script_bugtraq_id(10095);
	script_xref(name:"OSVDB", value:"5231");

	script_name(english:"X-Micro Router Default Password");
	script_summary(english:"Attempts to login to a default account");

	script_set_attribute(
	  attribute:"synopsis",
	  value:string(
	    "The remote host has a default username and password set for\n",
	    "the management console."
	  )
	);
	script_set_attribute(
	  attribute:"description", 
	  value:string(
	    "The remote host (probably a X-Micro Wireless Broadband router)\n",
	    "has a default username and password set for the management\n",
            "console.  This may be due to a backdoor in the firmware.\n",
	    "\n",
	    "This console provides read/write access to the router's\n",
	    "configuration. An attacker could take advantage of this to\n",
  	    "reconfigure the router and possibly re-route traffic."
	  )
	);
	script_set_attribute(
	  attribute:"see_also",
	  value:"http://archives.neohapsis.com/archives/bugtraq/2004-04/0183.html"
	);
	script_set_attribute(
	  attribute:"solution", 
	  value:"Upgrade to the latest version of the firmware."
	);
	script_set_attribute(
	  attribute:"cvss_vector", 
	  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C"
	);
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_family(english:"Misc.");
	script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

i = 0;
username[i++] = "super";
username[i++] = "1502";

port = get_http_port(default:80);

r = http_send_recv3(method:"GET", item: "/", port: port,
  username: "nessus", password: "n3ssus");
if (isnull(r)) exit(0, "The web server did not answer");

if (r[0] !~ "^HTTP.* 403 ") exit(0, "/ is not protected");

foreach u (username)
{
 r = http_send_recv3(method:"GET", item: "/", port: port,
   username: u, password: u);

 if (isnull(r)) exit(0, "The web server did not answer");

 if (r[0] =~ "^HTTP.* 200 ")
 {
  if ( report_verbosity > 0 )
  {
    report = strcat("
Nessus was able to exploit the issue by logging in
with the following username:password combination :

  ", u, ":", u, '\n');
    security_hole(port:port, extra:report);
  }
  else
   security_hole(port);
  exit(0);
 }
}

