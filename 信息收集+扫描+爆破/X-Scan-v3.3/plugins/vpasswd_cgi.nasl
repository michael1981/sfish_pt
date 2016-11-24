#
# (C) Tenable Network Security, Inc.
#

# References
# Date: Thu, 24 Oct 2002 10:41:48 -0700 (PDT)
# From:"Jeremy C. Reed" <reed@reedmedia.net> 
# To:bugtraq@securityfocus.com
# Subject: Re: vpopmail CGIapps vpasswd vulnerabilities
# In-Reply-To: <200210241126.33510.n.bugtraq@icana.org.ar>
# Message-ID: <Pine.LNX.4.43.0210241020040.25224-100000@pilchuck.reedmedia.net>
#


include("compat.inc");

if(description)
{
 script_id(11165);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(6038);
 script_xref(name:"OSVDB", value:"2088");
 
 script_name(english:"vpopmail-CGIApps vpasswd.cgi Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed which allow arbitrary 
code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The 'vpasswd.cgi' CGI is installed. Some versions do not 
properly check for special characters and allow a cracker 
to execute any command on your system.

*** Warning : Nessus solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem" );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of vpasswd.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (is_cgi_installed3(port: port, item:"/vpasswd.cgi"))
  security_hole(port);
