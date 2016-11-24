#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11917);
 script_version ("$Revision: 1.11 $");

 script_cve_id(
   "CVE-2003-1042",
   "CVE-2003-1043",
   "CVE-2003-1044",
   "CVE-2003-1045",
   "CVE-2003-1046"
 );
 script_bugtraq_id(8953);
 script_xref(name:"OSVDB", value:"2843");
 script_xref(name:"OSVDB", value:"6387");
 script_xref(name:"OSVDB", value:"6388");
 script_xref(name:"OSVDB", value:"6389");
 script_xref(name:"OSVDB", value:"6390");

 script_name(english:"Bugzilla Multiple Vulnerabilities (SQLi, ID)");
 script_summary(english:"Checks the Bugzilla version number");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application on the remote host has multiple SQL injection\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, he remote Bugzilla bug tracking\n",
     "is vulnerable to various flaws that may let a privileged user execute\n",
     "arbitrary SQL commands on this host, which may allow an attacker to\n",
     "obtain information about bugs marked as being confidential."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.3/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Bugzilla version 2.16.4 / 2.17.5 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
if(!get_port_state(port))exit(0);

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(16\.[0-3]|17\.[0-4]))[^0-9]*$",
       string:version))security_warning(port);
