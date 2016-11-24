#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#


include("compat.inc");

if(description)
{
 script_id(10698);
 script_version ("$Revision: 1.30 $");
 script_bugtraq_id(2513);
 script_xref(name:"OSVDB", value:"576");

 script_name(english:"WebLogic Encoded Request Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the list of the contents of arbitrary
directories hosted on the remote server." );
 script_set_attribute(attribute:"description", value:
"Requesting a URL with '%00', '%2e', '%2f' or '%5c' appended to it
makes some WebLogic servers dump the listing of the page directory,
thus showing potentially sensitive files. 

An attacker may also use this flaw to view the source code of JSP
files, or other dynamic content." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/3182" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/pub/advisory/37?printable=true" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebLogic 6.0 with Service Pack 1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"Make a request like http://www.example.com/%00/");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 StrongHoldNet");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function http_getdirlist(itemstr, port) {
 local_var buffer, data, encaps, exploit_url, rbuf, report;

 buffer = http_get(item:itemstr, port:port);
 rbuf   = http_keepalive_send_recv(port:port, data:buffer);
 if (! rbuf ) exit(0);
 data = tolower(rbuf);
 #debug_print(level: 2, 'Answer to GET ', itemstr, ' on port ', port, ': ', rbuf);
 if(("directory listing of" >< data) || ("index of" >< data))
 {
  # If itemstr = / we won't report anything but will exit the test to avoid FP.
  if(strlen(itemstr) > 1) 
  {
   if (report_verbosity)
   {
    report = string(
     "\n",
     "Nessus was able to obtain a directory listing using the following\n",
     "URL :\n",
     "\n",
     "  ", build_url(port:port, qs:itemstr), "\n"
    );
    if (report_verbosity > 1)
    {
     report = string(
      report,
      "\n",
      "Here are its contents :\n",
      "\n",
      rbuf
     );
    }
    security_warning(port:port, extra:report);
   }
   else security_warning(port);
  }
  exit(0);
 }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);

# Unless we're paranoid, make sure it's WebLogic
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "WebLogic Server" >!< banner) exit(0);
}

http_getdirlist(itemstr:"/", port:port);	# Anti FP
http_getdirlist(itemstr:"/%2e/", port:port);
http_getdirlist(itemstr:"/%2f/", port:port);
http_getdirlist(itemstr:"/%5c/", port:port);
http_getdirlist(itemstr:"/%00/", port:port);
