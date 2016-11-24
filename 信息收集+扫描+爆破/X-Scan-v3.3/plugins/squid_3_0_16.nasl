#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(40420);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2621", "CVE-2009-2622");
  script_bugtraq_id(35812);

  script_name(english:"Squid 3.0.STABLE16 / 3.10.11");
  script_summary(english:"Checks version of Squid");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to denial of service attacks." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching
server installed on the remote host is older than 3.0.STABLE17 or
3.1.0.12.  Such versions reportedly use incorrect bounds checking when
processing some requests or responses. 

Squid-2.x releases are not vulnerable." );
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2009_2.txt" );
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17446" );
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17448" );
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17483" );
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.0.STABLE17 or 3.1.0.12 or later or
apply the patch referenced in the project's advisory above." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy",3128, 8080);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/http_proxy");
if (!port)
{
  if (get_port_state(3128)) port = 3128;
  else port = 8080;
}

banner = get_squid_banner(port: port);
if (isnull(banner)) exit(0);

if (banner =~ "^[Ss]quid/3\.(0\.STABLE([0-9]|1[0-6])|1\.0\.([0-9]|1[01]))$")
{
  if (report_verbosity > 0)
  {
    report = strcat(
      '\nThe remote Squid proxy returned the following banner :\n\n ',
      banner, '\n\n',
     'Note that Nessus has not actually attempted to exploit this issue so\n',
     'it may be a false-positive.\n');
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The remote Squid proxy is not affected.");
