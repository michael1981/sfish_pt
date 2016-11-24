#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20738);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0254");
  script_bugtraq_id(16260);
  script_xref(name:"OSVDB", value:"22458");

  script_name(english:"Apache Tomcat / Geronimo Sample Script cal2.jsp time Parameter XSS");
  script_summary(english:"Checks for cal2.jsp cross-site scripting vulnerability in Geronimo");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is prone to a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Geronimo, an open-source J2EE
server from the Apache Software Foundation. 

The version of Geronimo installed on the remote host includes a JSP
application that fails to sanitize user-supplied input to the 'time'
parameter before using it to generate a dynamic webpage.  An attacker
can exploit this flaw to cause arbitrary HTML and script code to be
executed in a user's browser within the context of the affected web
site." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/geronimo_css.txt" );
 script_set_attribute(attribute:"see_also", value:"http://issues.apache.org/jira/browse/GERONIMO-1474" );
 script_set_attribute(attribute:"solution", value:
"Uninstall the example applications or upgrade to Geronimo version
1.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Geronimo w/ Jetty.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: Jetty" >!< banner) exit(0);
}


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';


# Try to exploit the flaw in cal2.jsp.
w = http_send_recv3(method:"GET",
  item:string(
    "/jsp-examples/cal/cal2.jsp?",
    'time="/>', urlencode(str:xss)
  ), 
  port:port
);
if (isnull(w)) exit(1," the web server did not answer");
res = w[2];

# There's a problem if we see our XSS.
if (string('INPUT NAME="time" TYPE=HIDDEN VALUE="/>', xss) >< res) {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
