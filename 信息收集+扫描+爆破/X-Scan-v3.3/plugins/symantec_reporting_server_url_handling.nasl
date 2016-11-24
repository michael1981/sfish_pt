#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(38653);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2009-1432");
 script_bugtraq_id(34668);
 script_xref(name:"OSVDB", value:"54131");
 script_xref(name:"Secunia", value:"34935");

 script_name(english:"Symantec Reporting Server Improper URL Handling Exposure");
 script_summary(english:"Tries to exploit URL handling weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The login page in the remote web server contains a URL handling error.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Symantec Reporting Server, a component of
Symantec AntiVirus Corporate Edition, Symantec Client Security, and
Symantec Endpoint Protection Manager that serves to create reports
about the use of Symantec antivirus products in an enterprise
environment. 

The installed version of Reporting Server includes user-supplied input
to the 'MSG' parameter of the 'Reporting/login/login.php' script on
the login page.  By tricking an authorized user into clicking on a
specially crafted link, an attacker can cause an arbitrary message to
be displayed, which in turn could facilitate phishing attacks against
the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed674302" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42400bc6 (Symantec Advisory)" );
 script_set_attribute(attribute:"solution", value:
"Upgrade at described in the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8014);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Unless we're paranoid, make sure it's IIS (required for Symantec Reporting Server).
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if(!banner || "Microsoft-IIS" >!< banner) exit(0);
}

magic = string(SCRIPT_NAME, "-", unixtime());
url = "/Reporting/Login/Login.php?MSG=" + magic;

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if (
  magic >< res[2] &&
  "<title>Reporting - Log" >< res[2] &&
  '<input type="hidden" name="destination"' >< res[2]
)
{
  if (report_verbosity > 0 )
  { 
    report = string(
      "\n",
      "Nessus was able to verify the issue with the following URL :\n",
      "\n", 
      "  ", build_url(port:port, qs:url), "\n"
  );
   security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
