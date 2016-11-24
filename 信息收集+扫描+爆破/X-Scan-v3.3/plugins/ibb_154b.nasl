#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21337);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-2317", "CVE-2006-2318", "CVE-2006-2319", "CVE-2006-2320", "CVE-2006-2321");
  script_bugtraq_id(17920);
  script_xref(name:"OSVDB", value:"25455");
  script_xref(name:"OSVDB", value:"25456");
  script_xref(name:"OSVDB", value:"25457");
  script_xref(name:"OSVDB", value:"25458");

  script_name(english:"IdealBB < 1.5.4b Multiple Vulnerabilities (XSS, SQLi, Upload, Traversal)");
  script_summary(english:"Checks version of Ideal BB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ideal BB, an ASP-based forum software. 

According to its banner, the version of Ideal BB installed on the
remote host reportedly allows an attacker to upload files with
arbitrary ASP code, to view files under the web root, and to launch
SQL injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045887.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ideal BB version 1.5.4b or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/idealbb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab default.asp.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (isnull(res)) exit(0);

  if (
    '<td><span class="smallthinlink">Ideal BB Version: ' >< res &&
    egrep(pattern:"Ideal BB Version: 0\.(0\..*|1\.([0-4]\..*|5\.([0-3].*|4(a|rc))))<", string:res)
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
