#
# (C) tenable Network Security, Inc.
#
# Ref:
# Date: Fri, 25 Apr 2003 04:40:33 -0400
# To: bugtraq@securityfocus.com, announce@bugzilla.org,
# From: David Miller <justdave@syndicomm.com>
# Subject: [BUGZILLA] Security Advisory - XSS, insecure temporary filenames
	

include("compat.inc");

if(description)
{
 script_id(11553);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2003-0602", "CVE-2003-0603");
 script_bugtraq_id(6861, 6868, 7412);
 script_xref(name:"OSVDB", value:"6348");
 script_xref(name:"OSVDB", value:"6349");
 script_xref(name:"OSVDB", value:"6350");
 script_xref(name:"OSVDB", value:"6383");
 script_xref(name:"OSVDB", value:"6384");
 script_xref(name:"OSVDB", value:"6385");

 script_name(english:"Bugzilla < 2.16.3 / 2.17.4 Multiple Vulnerabilities (XSS, Symlink)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, contains various flaws that may let an attacker perform cross-
site scripting attacks or even delete local files (provided he has an
account on the remote host)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.16.3 / 2.17.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of bugzilla");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-2]|17\.[0-3]))[^0-9]*$",
       string:version)){
		 security_warning(port);
		 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
       
