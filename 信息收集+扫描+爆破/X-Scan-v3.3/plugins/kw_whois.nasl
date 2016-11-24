#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10541);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2000-0941");
 script_bugtraq_id(1883);
 script_xref(name:"OSVDB", value:"440");

 script_name(english:"KW Whois CGI whois Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/whois.cgi");

 script_set_attribute(
  attribute:"synopsis",
  value:
"The remote web server hosts a CGI script that allows execution of
arbitrary commands."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The version of the KW whois CGI script installed on the remote web
server fails to filter input to the 'whois' parameter of shell
metacharacters.  An unauthenticated remote attacker can leverage this
issue to execute arbitrary commands with the privileges of the http
daemon."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2000-10/0419.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2000/10/29"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/29"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/whois.cgi?action=load&whois=%3Bid",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
