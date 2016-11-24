#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17687);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0524", "CVE-2005-0525");
  script_bugtraq_id(12962, 12963);
  script_xref(name:"OSVDB", value:"15183");
  script_xref(name:"OSVDB", value:"15184");

  script_name(english:"PHP Multiple Image Processing Functions File Handling DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is vulnerable to a denial of service attack due to its failure to
properly validate file data in the routines 'php_handle_iff' and
'php_handle_jpeg', which are called by the PHP function
'getimagesize'.  Using a specially crafted image file, an attacker can
trigger an infinite loop when 'getimagesize' is called, perhaps even
remotely in the case image uploads are allowed." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=222" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/394797" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_4_3_11.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.11 / 5.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_summary(english:"Checks for image file format denial of service vulnerabilities in PHP");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


banner = get_http_banner(port:port);
if (!banner) exit(0);

php = get_php_version(banner:banner);
if (
  php && 
  ereg(string:php, pattern:"PHP/([0-3]\.|4\.[0-2]\.|4\.3\.([0-9][^0-9]+|10[^0-9]+)|5\.0\.[0-3][^0-9]+)")
) security_warning(port);
