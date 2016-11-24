#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(13635);
 script_version ("$Revision: 1.12 $");

 script_cve_id(
  "CVE-2004-0702",
  "CVE-2004-0703",
  "CVE-2004-0704",
  "CVE-2004-0705",
  "CVE-2004-0706",
  "CVE-2004-0707"
 );
 script_bugtraq_id(10698);
 script_xref(name:"OSVDB", value:"7782");
 script_xref(name:"OSVDB", value:"7786");
 script_xref(name:"OSVDB", value:"7787");
 script_xref(name:"OSVDB", value:"7788");
 script_xref(name:"OSVDB", value:"7789");
 script_xref(name:"OSVDB", value:"7790");
 script_xref(name:"OSVDB", value:"7791");

 script_name(english:"Bugzilla < 2.16.6 / 2.18rc1 Multiple Vulnerabilities (XSS, SQLi, Priv Esc, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, is vulnerable to various flaws :

- An administratrator may be able to execute arbitrary SQL commands on
the remote host. 

- There are instances of information leaks which may let an attacker
know the database password (under certain circumstances, 2.17.x only)
or obtain the names of otherwise hidden products. 

- A user with grant membership privileges may escalate his privileges
and belong to another group. 
 
- There is a cross site scripting issue in the administrative web
interface. 

- Users passwords may be embedded in URLs (2.17.x only). 

- Several information leaks that may allow users to determine the
names of other users and non-users to obtain a list of products,
including those that administrators might want to keep confidential." );
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.16.6 or 2.20 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "Checks for the presence of bugzilla"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("bugzilla_detect.nasl");
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


if(ereg(pattern:"(1\..+|2\.(16\.[0-5]|1[789]\..+|2(0 *rc.*|1))[^0-9]*$)",
       string:version)) {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

