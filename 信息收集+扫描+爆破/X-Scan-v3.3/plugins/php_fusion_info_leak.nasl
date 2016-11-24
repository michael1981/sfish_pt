#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(16336);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0345");
 script_bugtraq_id(12482);
 script_xref(name:"OSVDB", value:"13920");
 
 script_name(english:"PHP-Fusion < 5.00 viewthread.php Arbitrary Message Thread / Forum Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to read the content of arbitrary forums and threads,
regardless of his privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/389733" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Fusion 5.00 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("php_fusion_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = items[1];

if ( ereg(pattern:"^([0-4][.,])", string:version) )
	security_warning(port);
