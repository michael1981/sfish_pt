#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11764);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(7969);
 script_xref(name:"OSVDB", value:"54805");
 
 script_name(english:"TMaxSoft JEUS url.jsp URI XSS");
 script_summary(english:"Checks for TMax Jeus");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a cross-site\n",
     "scripting vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Tmax Soft JEUS, a web application\n",
     "written in Java.\n\n",
     "Input to the query string is not properly sanitized, which could\n",
     "lead to a cross-site scripting attack.  A remote attacker could\n",
     "exploit this by tricking a user into requesting a maliciously\n",
     "crafted URL.  This would allow the attacker to impersonate the\n",
     "targeted user."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q2/1426.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

test_cgi_xss(port: port, cgi: "/url.jsp", dirs: cgi_dirs(), 
 qs: "<script>foo</script>", pass_re: "<script>foo</script>");
