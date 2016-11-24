#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18047);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2005-1112");
 script_bugtraq_id(13160);
 script_xref(name:"OSVDB", value:"15501");
 
 script_name(english:"IBM WebSphere Application Server Malformed Host Header JSP Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server disclose the source code
of its JSP pages by requesting the pages with a nonexistent hostname
in the HTTP 'Host' header request when WebSphere Application is
sharing the document root of the web server.  An attacker may use this
flaw to get the source code of your CGIs and possibly to obtain
passwords and other relevant information about this host." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111342594129109&w=2" );
 script_set_attribute(attribute:"solution", value:
"Move JSP source files outside the web server document root." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Attempts to read the source of a jsp page");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(file, hostname)
{
 local_var res,w ;
 global_var port;

 w = http_send_recv3(method:"GET", item: file, version: 11, host: hostname, port: port);
 if (isnull(w)) exit(0);
 res = w[2];
 if("<%" >< res) return(1);
 return 0;
}

port = get_http_port(default:80);

 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/index.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file, hostname:get_host_name()) == 0)
   {
   if(check(file:file, hostname:"sjfklsjfkldfjklsdfjdlksjfdsljk.foo."))
   { 
    if (report_verbosity)
    {
     req = str_replace(find:'\n', replace:'\n  ', string: http_last_sent_request());
     report = string(
      "\n",
      "Nessus was able to exploit the issue using the following\n",
      "request :\n",
      "\n",
      "  ", req, "\n"
     );
     if (report_verbosity > 1)
     {
      res = str_replace(find:'\n', replace:'\n  ', string:res);
      report = string(
       report,
       "\n",
       "Here is the JSP source received :\n",
       "\n",
       res
      );
     }
     security_note(port:port, extra:report);
    }
    else security_note(port);

    exit(0);
   }
  }
  n ++;
  if(n > 20)exit(0);
 }

