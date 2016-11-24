#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11653);
 script_version ("$Revision: 1.12 $");

 script_bugtraq_id(5504, 5509, 5510, 5514, 5515, 5563, 5565);
 script_cve_id(
  "CVE-2002-1110",
  "CVE-2002-1111",
  "CVE-2002-1112",
  "CVE-2002-1113",
  "CVE-2002-1114",
  "CVE-2002-1115",
  "CVE-2002-1116"
 );
 script_xref(name:"OSVDB", value:"4858");

 script_name(english:"Mantis < 0.17.5 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Mantis on the remote host
contains various flaws that may allow an atacker to execute arbitrary
commands, inject SQL commands, view bugs it should not see, and get a
list of projects that should be hidden." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0176.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0177.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0184.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0186.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0187.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0253.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0255.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.17.5 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english: "Checks for the version of Mantis");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-6]\.|17\.[0-4][^0-9])", string:ver))
	security_hole(port);
}	
