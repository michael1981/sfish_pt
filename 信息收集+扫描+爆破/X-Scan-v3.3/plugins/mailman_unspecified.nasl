#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16136);
 script_bugtraq_id(12243);
 script_version("$Revision: 1.5 $");

 script_name(english:"GNU Mailman Multiple Unspecified Remote Vulnerabilities");
 script_summary(english:"GNU Mailman unspecified vulnerabilities");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A web application on the remote host has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running GNU Mailman, a web-based application\n",
     "for managing mailing lists.  The version running on the remote\n",
     "host has multiple flaws, such as information disclosure and\n",
     "cross-site scripting.  These vulnerabilities could allow a\n",
     "remote attacker to gain unauthorized access."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencie("mailman_password_retrieval.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/Mailman");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([0-1]\.|2\.(0\.|1\.[0-5][^0-9]))", string:version) )
{
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

