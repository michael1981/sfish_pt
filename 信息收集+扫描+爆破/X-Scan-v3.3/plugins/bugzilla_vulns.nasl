#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11463);
 script_version ("$Revision: 1.15 $");
 if ( NASL_LEVEL >= 3004 )
 {
  script_cve_id(
   "CVE-2002-0803",
   "CVE-2002-0804",
   "CVE-2002-0805",
   "CVE-2002-0806",
   "CVE-2002-0807",
   "CVE-2002-0808",
   "CVE-2002-0809",
   "CVE-2002-0810",
   "CVE-2002-0811",
   "CVE-2002-1196",
   "CVE-2002-1197",
   "CVE-2002-1198",
   "CVE-2002-2260",
   "CVE-2003-0012",
   "CVE-2003-0013"
  );
 }
 script_bugtraq_id(4964, 5842, 5843, 5844, 6257, 6501, 6502);
 script_xref(name:"OSVDB", value:"5080");
 script_xref(name:"OSVDB", value:"6351");
 script_xref(name:"OSVDB", value:"6352");
 script_xref(name:"OSVDB", value:"6353");
 script_xref(name:"OSVDB", value:"6354");
 script_xref(name:"OSVDB", value:"6355");
 script_xref(name:"OSVDB", value:"6356");
 script_xref(name:"OSVDB", value:"6357");
 script_xref(name:"OSVDB", value:"6394");
 script_xref(name:"OSVDB", value:"6395");
 script_xref(name:"OSVDB", value:"6397");
 script_xref(name:"OSVDB", value:"6398");
 script_xref(name:"OSVDB", value:"6399");
 script_xref(name:"OSVDB", value:"6400");
 script_xref(name:"OSVDB", value:"6401");

 script_name(english:"Bugzilla < 2.14.2 / 2.16rc2 / 2.17 Multiple Vulnerabilities (SQLi, XSS, ID, Cmd Exe)");
 script_summary(english:"Checks the Bugzilla version number");
 
  script_set_attribute(
   attribute:"synopsis",
   value:"The remote bug tracker has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote Bugzilla bug tracking\n",
     "system is vulnerable to various flaws, including SQL injection,\n",
     "cross-site scripting, and arbitrary command execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.14.2/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.1/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.1-nr/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Bugzilla version 2.14.5 / 2.16.2 / 2.17.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\.[0-4]|15\..*|16\.[0-1]|17\.[0-2]))[^0-9]*$",
       string:version))security_hole(port);
       
       
