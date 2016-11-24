#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22115);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-3430");
  script_bugtraq_id(18715);
  script_xref(name:"OSVDB", value:"26925");

  script_name(english:"PatchLink Update Server checkprofile.asp checkid Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in PatchLink Update");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to sanitize user-supplied input to the 'agentid' parameter of the
'/dagent/checkprofile.php' script before using it to construct
database queries.  An unauthenticated attacker can exploit this flaw
to manipulate database queries, which might lead to disclosure of
sensitive information, modification of data, or attacks against the
underlying database. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/438710/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Try to exploit the flaw to generate a SQL error.
r = http_send_recv3(method:"GET", port: port,
  item:string(
    "/dagent/checkprofile.asp?",
    "agentid=11111'", SCRIPT_NAME ) );
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if we see an error with our script name.
if (
  "Microsoft OLE DB Provider for SQL Server" >< res &&
  "error '80040e14'" >< res &&
  # nb: the error message does not include the script's extension.
  string("Incorrect syntax near '", (SCRIPT_NAME - strstr(SCRIPT_NAME, "."))) >< res
) {
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
