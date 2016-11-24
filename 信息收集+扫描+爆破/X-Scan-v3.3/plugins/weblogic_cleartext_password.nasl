#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11627);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-1224", "CVE-2003-1225", "CVE-2003-1226");
 script_bugtraq_id(7563, 7587);
 script_xref(name:"OSVDB", value:"19800");
 script_xref(name:"OSVDB", value:"19801");
 script_xref(name:"OSVDB", value:"19803");
 script_xref(name:"OSVDB", value:"19804");
 script_xref(name:"OSVDB", value:"19805");
 
 script_name(english:"WebLogic Multiple Method Cleartext Password Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected to information disclosure issues." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running WebLogic 7.0 or 7.0.0.1.

There is a bug in these versions that may allow a local attacker to
recover a WebLogic password if he can see the screen of the WebLogic
server. 

In addition, a local user may be able to view cryptographic secrets,
thereby facilitating cracking of encrypted passwords." );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-30.jsp" );
 script_set_attribute(attribute:"solution", value: "Apply Service Pack 3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks the version of WebLogic");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);

if (" Temporary Patch for CR104520" >< banner) exit(0);


if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  security_note(port);
  exit(0);
}

