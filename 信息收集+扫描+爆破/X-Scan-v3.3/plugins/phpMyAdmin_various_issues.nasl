#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(15948);
 script_version("$Revision: 1.8 $");

 script_bugtraq_id(11886); 
 script_cve_id("CVE-2004-1147", "CVE-2004-1148");
 script_xref(name:"OSVDB", value:"12330");
 script_xref(name:"OSVDB", value:"12331");

 script_name(english:"phpMyAdmin < 2.6.1-rc1 Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of phpMyAdmin is
vulnerable to one (or both) of the following flaws :

- An attacker may be able to exploit this software to execute
arbitrary commands on the remote host on a server which does not run
PHP in safe mode. 

- An attacker may be able to read arbitrary files on the remote host
through the argument 'sql_localfile' of the file 'read_dump.php'." );
 script_set_attribute(attribute:"see_also", value:"http://www.exaprobe.com/labs/advisories/esa-2004-1213.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0115.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.6.1-rc1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english:"Checks the version of phpMyAdmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/phpMyAdmin");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
# Only 2.4.0 to 2.6.0plX affected
if (matches[1] && ereg(pattern:"^(2\.[45]\..*|2\.6\.0|2\.6\.0-pl)", string:matches[1]))
	security_warning(port);
