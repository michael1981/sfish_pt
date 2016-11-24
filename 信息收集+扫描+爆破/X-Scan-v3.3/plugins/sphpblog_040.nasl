#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19516);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-2733", "CVE-2005-2787");
  script_bugtraq_id(14667, 14681);
  script_xref(name:"OSVDB", value:"19012");
  script_xref(name:"OSVDB", value:"19070");

  name["english"] = "Simple PHP Blog <= 0.4.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Simple PHP Blog installed on the remote host allows
authenticated attackers to upload files containing arbitrary code to
be executed with the privileges of the web server userid. 

In addition, it likely lets anyone retrieve its configuration file as
well as the user list and to delete arbitrary files subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0885.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0401.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f3599b" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simple PHP Blog 0.4.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Simple PHP Blog <= 0.4.0";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("sphpblog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  dir = matches[2];

  # Get the blog's title.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  title = "";
  pat = "<title>(.+)</title>";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches, keep:FALSE)) {
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        title = title[1];
        break;
      }
    }
  }

  # Check whether the title is stored as the first field of config.txt.
  if (!isnull(title)) {
    req = http_get(item:string(dir, "/config.txt"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    # There's a problem if the first field is the title.
    if (egrep(string:res, pattern:string("^", title, "|"))) {
      security_hole(port);
      exit(0);
    }
  }

  # If that didn't work, check the version number.
  if (ver && ver =~ "^0\.([0-3]|4\.0)") {
    report = string(
      "\n",
      "Note that Nessus has determined the vulnerabilities exist on the\n",
      "remote host simply by looking at the version number of Simple\n",
      "PHP Blog installed there.\n"
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
