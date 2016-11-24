#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32433);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-2240", "CVE-2008-2410");
  script_bugtraq_id(29310, 29311);
  script_xref(name:"OSVDB", value:"45414");
  script_xref(name:"OSVDB", value:"45415");
  script_xref(name:"Secunia", value:"30310");

  script_name(english:"IBM Lotus Domino < 8.0.1 / 7.0.3 FP1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Lotus Domino on the remote
host is older than 8.0.1 / 7.0.3 FP1.  The web server component of
such versions is reportedly affected by a stack overflow that can be
triggered by means of a specially-crafted 'Accept-Language' request
header.  While IBM only says this results in a denial of service, the
original researchers claim to have a working proof-of-concept for
Windows that allows arbitrary code execution with LOCAL SYSTEM
privileges. 

In addition, the web server reportedly has an unspecified cross-site
scripting vulnerability in its servlet engine / Web container." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3b5cab6" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21303057" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21303296" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 8.0.1 / 7.0.3 FP1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("domino_installed.nasl", "http_version.nasl");
  script_require_keys("Domino/Version");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're being paranoid, make sure a Domino web server is listening.
if (report_paranoia < 2)
{
  port = get_http_port(default:80);
  banner = get_http_banner(port:port);
  if (!banner || "Domino" >!< banner) exit(0);
}
else port = 0;


# Check the version of Domino installed.
ver = get_kb_item("Domino/Version");
if (isnull(ver)) exit(0);

if (
  egrep(pattern:"^7\.0($|\.([0-2]($|[^0-9])|3$))", string:ver) ||
  egrep(pattern:"^8\.0($|\.0($|[^0-9]))", string:ver)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Domino version ", ver, " appears to be installed on the remote host.\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
