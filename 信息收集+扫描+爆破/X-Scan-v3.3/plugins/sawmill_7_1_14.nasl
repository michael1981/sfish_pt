#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19681);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2950");
  script_bugtraq_id(14789);
  script_xref(name:"OSVDB", value:"19254");

  script_name(english:"Sawmill < 7.1.14 GET Request Query String XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sawmill, a weblog analysis package. 

The version of Sawmill installed on the remote host suffers from a
cross-site scripting flaw because its standalone web server treats an
arbitrary query string appended to a GET request as a configuration
command and fails to sanitize it before using it in an error page.  An
unauthenticated attacker may be able to exploit this issue to steal
authentication information of users of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.nta-monitor.com/news/xss/sawmill/index.htm" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-09/0114.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sawmill 7.1.14 or later or use Sawmill in CGI mode." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for cross-site scripting vulnerability in Sawmill < 7.1.14";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8987);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:8987);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# The flaw only affects Sawmill's built-in web server.
banner = get_http_banner(port:port);
if (banner && "Server: Sawmill/" >< banner) {
  req = http_get(
    item:string("/?", rand_str(), "=", exss),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (xss >< res)
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
