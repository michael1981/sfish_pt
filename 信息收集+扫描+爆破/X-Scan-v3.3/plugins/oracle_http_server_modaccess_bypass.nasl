#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18181);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1383");
  script_bugtraq_id(13418);
  script_xref(name:"OSVDB", value:"15908");

  script_name(english:"Oracle Application Server Webcache Requests OHS mod_access Restriction Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server (OHS) installed on the remote host
fails to prevent users from accessing protected URLs by using the Web
Cache rather than OHS directly." );
 script_set_attribute(attribute:"see_also", value:"http://www.red-database-security.com/advisory/oracle_webcache_bypass.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0486.html" );
 script_set_attribute(attribute:"solution", value:
"Enable 'UseWebCacheIP' in OHS's httpd.conf." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for mod_access restriction bypass vulnerability in Oracle HTTP Server");
  script_category(ACT_ATTACK);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7777, 7778);
  script_require_keys("www/OracleApache");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# We need to locate both OHS and Web Cache.
list = get_kb_list("Services/http");
if (isnull(list)) exit(0);
list = make_list(list);
foreach port (list) {
  banner = get_http_banner(port:port);

  # nb: the banner for Web Cache likely includes the string 
  #     "Oracle-HTTP-Server" as well so check for it first.
  if (banner && "OracleAS-Web-Cache" >< banner) webcache_port = port;
  else if (banner && "Oracle-HTTP-Server" >< banner) ohs_port = port;
  if (webcache_port && ohs_port) break;
}
if (!webcache_port || !ohs_port) exit(0);
if (!get_port_state(webcache_port) || !get_port_state(ohs_port)) exit(0);
if (get_kb_item("www/no404/" + webcache_port)) exit(0);


# Try to access some normally protected URIs.
uris = make_list(
  '/dms0',
  '/dmsoc4j/AggreSpy?format=metrictable&nountype=ohs_child&orderby=Name',
  '/server-status'
);
foreach uri (uris) {
  # Try to access them first through OHS to make sure that they
  # exist and are protected.
  w = http_send_recv3(method:"GET", item:"uri", port:ohs_port);
  if (isnull(w)) exit(1, "the web server did not answer");

  if (w[0] !~ "^HTTP/.* 403 Forbidden") continue;

  # Now try going through Web Cache.
  w = http_send_recv3(method:"GET", item:"uri", port:webcache_port);
  if (isnull(w)) exit(1, "the web server did not answer");
  # It's a problem if this worked.
  if (w[0] =~ "^HTTP/.* 200 OK")
  {
    security_note(ohs_port);
    exit(0);
  }
}
