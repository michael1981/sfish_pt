#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15931);
 script_cve_id("CVE-2004-1223");
 script_bugtraq_id(11869);
 script_xref(name:"OSVDB", value:"12289");
 script_xref(name:"Secunia", value:"13416");
 script_version ("$Revision: 1.5 $");
 
 script_name(english:"F-Secure Policy Manager Path Disclosure");
 script_summary(english:"Checks for /fsms/fsmsh.dll");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an information\n",
     "disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running F-Secure Policy Manager, a distributed\n",
     "administration software allowing a system administrator to control\n",
     "applications from a single web console.\n\n",
     "There is a flaw in the file '/fsms/fsmsh.dll' which discloses the\n",
     "physical path this application is under.  An attacker could use this\n",
     "information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0103.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
url = '/fsms/fsmsh.dll?';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The server didn't respond");

if ("Commdir path" >< res[2])
{
  if (report_verbosity > 0)
  {
    report = string(
      "Nessus exploited this issue by requesting the following URL :\n\n",
      "  ", build_url(qs:url, port:port), "\n"
    );

    if (report_verbosity > 1)
      report += string("\nWhich yielded :\n\n", res[2], "\n");

    security_warning(port:port, extra:res[2]);
  }
  else security_warning(port);
}
