#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19415);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1527");
  script_bugtraq_id(14525);
  script_xref(name:"OSVDB", value:"18696");

  name["english"] = "AWStats Referrer Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool for
analyzing ftp, mail, web, ...  traffic. 

The version of AWStats installed on the remote host collects data
about the web referrers and uses them without proper sanitation in an
eval() statement.  Using specially-crafted referrer data, an attacker
can cause arbitrary Perl code to be executed on the remote host within
the context of the affected application once the stats page has been
regenerated and when a user visits the referer statistics page. 

Note that successful exploitation requires that at least one URLPlugin
is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=290" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0239.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0371.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to AWStats 6.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for referrer arbitrary command execution vulnerability in AWStats";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("awstats_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  ver = NULL;
  ver = matches[1];

  if ("unknown" >< ver) exit(0);

  # Check the version number.
  if (ver && ver =~ "^([0-5]\.|6\.[0-4]^[0-9]?)") 
  {
    security_warning(port);
    exit(0);
  }
}
