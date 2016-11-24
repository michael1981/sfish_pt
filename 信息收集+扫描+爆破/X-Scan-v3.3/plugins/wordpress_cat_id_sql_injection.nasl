#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18420);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1810");
  script_bugtraq_id(13809);
  script_xref(name:"OSVDB", value:"16905");

  script_name(english:"WordPress template-functions-category.php cat_ID Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
properly sanitize user-supplied input to the 'cat_ID' variable in the
'template-functions-category.php' script.  This failure may allow an
attacker to influence database queries resulting in the disclosure of
sensitive information and possibly attacks against the underlying
database itself. 

Note that Nessus has determined the vulnerability exists on the remote
host simply by checking the version number of WordPress installed
there." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111817436619067&w=2 " );
 script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2005/05/security-update/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.5.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for cat_ID SQL injection vulnerability in WordPress";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0\.|1\.([0-4]|5([^0-9.]+|$|\.0|\.1([^0-9.]|$)|\.1\.[01][^0-9])))") {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
