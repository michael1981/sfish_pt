#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(15763);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-2456");
 script_bugtraq_id(11688);
 script_xref(name:"OSVDB", value:"11711");

 script_name(english:"miniBB index.php user Variable SQL Injection");
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary SQL commands");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a SQL injection vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using the miniBB forum management system.\n\n",
     "According to its version number, this forum is vulnerable to a\n",
     "SQL injection attack.  Input to the 'user' parameter of index.php\n",
     "not properly sanitized.  A remote attacker could exploit this to\n",
     "execute arbitrary SQL queries against the remote database."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to miniBB 1.7f or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("minibb_xss.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/minibb");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (.*)$");
if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7([a-e]|$))", string:matches[1]) )
{
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
