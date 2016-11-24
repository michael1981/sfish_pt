#
# (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(14188);
 script_cve_id("CVE-2004-2257");
 script_bugtraq_id(10813);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8240");
 }
 script_version("$Revision: 1.9 $");

 name["english"] = "phpMyFAQ Image Upload Authentication Bypass";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows for
unauthorized file uploads." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyFAQ on the remote host contains a flaw that may
allow an attacker without authorization to upload and delete arbitrary
images on the remote host.  An attacker may exploit this problem to
deface the remote web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2004-07-27.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.4.0a or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Check the version of phpMyFAQ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpmyfaq_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "(0\.|1\.([0-3]\.|4\.0[^a]))") security_hole(port);
}
