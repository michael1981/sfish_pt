#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(42083);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3029", "CVE-2009-3030"); 
  script_bugtraq_id(36570, 36571);
  script_xref(name:"OSVDB", value:"58650");
  script_xref(name:"OSVDB", value:"58651");
  script_xref(name:"Secunia", value:"36972");

  script_name(english:"Symantec SecurityExpressions Audit and Compliance Server Multiple XSS");
  script_summary(english:"Checks version in about.aspx");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple cross-site scripting vulnerabilities." );

  script_set_attribute(attribute:"description", value:
"Symantec SecurityExpressions Audit and Compliance Server is installed
on the remote host.  The installed version is affected by multiple
cross-site scripting vulnerabilities. 

  - The web console fails to sanitize user supplied input 
    to certain unspecified parameters. An authorized user may
    be able to exploit this issue to inject arbitrary HTML or 
    script code into an user's browser to be executed 
    within the security context of the affected site.

  - Certain error messages are not properly encoded which 
    could be exploited by an attacker to inject arbitrary 
    HTML content into an user's browser session." );

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2eb105ca" );

  script_set_attribute(attribute:"solution", value:
"Apply Hot Fix 1 as referenced in article KB49452." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port =  get_http_port(default:80);

if (!can_host_asp(port:port))  exit(0, "The web server on port "+port+" does not support ASP scripts.");

res = http_send_recv3(port:port, method:"GET", item:"/seserver/about.aspx");
if(isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if('bold">SecurityExpressions Audit &amp; Compliance&nbsp;Server Version' >!< res[2]) 
  exit(0, "SecurityExpressions Audit & Compliance Server is not installed.");

match  = strstr(res[2],'<span id="VersionNum');
match  = match - strstr(match,'</span></td>') - '<span id="VersionNum">' ;

version = NULL;
build   = 0;

if(ereg(pattern:"^[0-9.]+ *\[Build *[0-9]+\]$",string:match))
{
  matches = eregmatch(pattern:"^([0-9.]+) *\[Build *([0-9]+)\]$",string:match);
  version = matches[1];
  build   = matches[2];
}
else if (ereg(pattern:"^[0-9.]+ *$",string:match))
{
  matches = eregmatch(pattern:"^([0-9.]+) *$",string:match);
  version = matches[1];
}

if(isnull(version)) exit(1, "Could not get version.");

v = split(version,sep:".",keep:FALSE);
for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

if( (v[0]  < 4) ||
    (v[0] == 4 && v[1]  < 1) ||
    (v[0] == 4 && v[1] == 1 && v[2]  < 1) ||
    (v[0] == 4 && v[1] == 1 && v[2] == 1 && build < 83) 
  )
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = string("\n",
               "SecurityExpressions Audit & Compliance Server Version ",version);
    if(!isnull(build)) report += string(" [Build ",build,"]"); 
   
    report += string('\n', "is installed on the remote host.");     
    security_warning(port:port,extra:report);   
  }
   else
    security_warning(port);   
}
else
  exit(0,"The web server on port "+port+" is not affected since SecurityExpressions Audit & Compliance Server "+match+" is installed on it.");
