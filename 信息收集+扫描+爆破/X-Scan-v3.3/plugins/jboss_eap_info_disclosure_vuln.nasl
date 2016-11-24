#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33869);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3273");
  script_bugtraq_id(30540);
  script_xref(name:"OSVDB", value:"47551");

  script_name(english:"JBoss Enterprise Application Platform (EAP) Status Servlet Request Remote Information Disclosure");
  script_summary(english:"Attempts to access status servlet without credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a servlet that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform (EAP) running on
the remote host allows unauthenticated access to status servlet, which
is used to monitor sessions and requests sent to the server." );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=457757" );
 script_set_attribute(attribute:"see_also", value:"http://jira.jboss.com/jira/browse/JBPAPP-544 (login required)" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JBoss EAP version 4.2.0.CP03 / 4.3.0.CP01." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Check if we are looking at JBoss EAP
banner = get_http_banner(port:port);
if (!banner || "JBoss" >!< banner ) exit(0);


# Try to access the status servlet.
exploit = "/status?full=true";
req = http_get(item:exploit, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If the info looks like it is coming from status servlet ...
if (
  "Application list"      >< res &&
  "Status Servlet" 	  >< res &&
  "Processing time"       >< res
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to access the status servlet using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:exploit), "\n"
    );
    if (report_verbosity > 1 && "Application list</h1><p>" >< res)
    {
      # Report the application list.
      apps = strstr(res, "Application list</h1><p>") - "Application list</h1><p>";
      if ("</p>" >< apps) apps = apps - strstr(apps, "</p>");
      if (egrep(pattern:"<(h[0-9]|a class)", string:apps)) apps = "";
      else
      {
        apps = str_replace(find:"<br>", replace:'\n  ', string:apps);
        apps = ereg_replace(pattern:"<[^>]+>", replace:"", string:apps);
      }

      if (apps)
      {
        report = string(
          report,
          "\n",
          "Here is the Application list as reported by that servlet :\n",
          "\n",
          "  ", apps, "\n"
        );
       }
    }
    security_warning(port:port, extra:report);	
  }
  else security_warning(port);
}
    
 






