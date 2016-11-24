#
# (C) Tenable Network Security, Inc.
#

# This flaw is a pain to check for. We rely on the banner, and if that fails,
# we'll have to rely on the behavior of the remote server when it comes
# to 30x redirections.


include("compat.inc");

if(description)
{
 script_id(11386);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0178");
 script_bugtraq_id(6870, 6871);
 script_xref(name:"OSVDB", value:"10823");
 script_xref(name:"OSVDB", value:"10826");

 script_name(english:"IBM Lotus Domino 6.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Lotus Domino server, according to its version number,
is vulnerable to various buffer overflows and denial
of service attack.

An attacker may use these to disable this server or
execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/advisories/lotus-hostlocbo.txt" );
 script_set_attribute(attribute:"solution", value:
"Update to Domino 6.0.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the version of the remote Domino Server");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);

banner = get_http_banner(port:port);

if(egrep(pattern:"Lotus-Domino/(Release-)?[1-5]\..*", string:banner))
 {
  exit(0);
 }


if(egrep(pattern:"Lotus-Domino/6\.(0|0\.0)[^0-9]$", string:banner))
{
 security_hole(port);
 exit(0);
}

if(safe_checks()) exit(0);

#
# Next, we try a generic check, in case of the redirection
# is set for the start web page (happens often)


#
# Finally, we try the check for every 30x page that webmirror.nasl
# encountered
#

redirs = get_kb_list(string("www/", port, "/content/30x"));
if(isnull(redirs))redirs = make_list("/");
else redirs = make_list(redirs, "/");

foreach url (redirs)
{
 r = http_send_recv3(port:port, method: "GET", item: url, version: 11, host: "foobar");
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:"https?://foobar/", string: res)){
 	r = http_send_recv3(port:port, method: "GET", item: url, version: 11, host: crap(400));
	if (isnull(r)) security_hole(port);
	else {
	 res = strcat(r[0], r[1], '\r\n', r[2]);
	 if("Domino" >< res)
	 {
	  if(ereg(pattern:"^HTTP/1\.[01] 3", string: r[0]))
	  {
	  security_hole(port);
	  exit(0);
	  }
	 }
	}
       }
}
