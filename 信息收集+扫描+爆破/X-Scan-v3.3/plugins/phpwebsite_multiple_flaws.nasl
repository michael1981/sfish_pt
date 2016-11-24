#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description) {
  script_id(11816);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2003-0735", "CVE-2003-0736", "CVE-2003-0737", "CVE-2003-0738");
  script_xref(name:"OSVDB", value:"2410");
  script_xref(name:"OSVDB", value:"3842");
  script_xref(name:"OSVDB", value:"3843");
  script_xref(name:"OSVDB", value:"3844");
  script_xref(name:"OSVDB", value:"3845");
  script_xref(name:"OSVDB", value:"3846");
  script_xref(name:"OSVDB", value:"3847");

  script_name(english:"phpWebSite < 0.9.x Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"There are multiple flaws in the remote version of phpWebSite that may
allow an attacker to gain the control of the remote database, or to
disable this site entirely." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q3/1659.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"SQL Injection and more.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpwebsite_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  r = http_send_recv3(method:"GET", item:dir + "/index.php?module=calendar&calendar[view]=day&year=2003%00-1&month=", port:port);
  if(isnull(r))exit(0);
  buf = r[2];

  if(egrep(pattern:".*select.*mod_calendar_events.*", string:buf)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
