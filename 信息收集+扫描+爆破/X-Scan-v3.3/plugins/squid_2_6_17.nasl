#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29216);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-6239", "CVE-2008-1612");
  script_bugtraq_id(26687, 28693);
  script_xref(name:"OSVDB", value:"39381");
  script_xref(name:"OSVDB", value:"44276");

  script_name(english:"Squid < 2.6.STABLE18 Cache Update Reply Unspecified DoS");
  script_summary(english:"Checks version of Squid");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is older than 2.6.STABLE18.  Such
versions reportedly use incorrect bounds checking when processing some
cache update replies.  A client trusted to use the service may be able
to leverage this issue to crash the application, thereby denying
service to legitimate users. 

Note that an earlier version of the advisory said 2.6.STABLE17 fixed
the issue, but it turned out that the patch did not fully address the
issue." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2007_2.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484662/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 2.6.STABLE18 or later or apply the
patch referenced in the project's advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy",3128, 8080);

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
if (!get_port_state(port)) exit(0);


banner = get_squid_banner(port: port);
  if (
    !isnull(banner) && 
    banner =~ "^[Ss]quid/([01]\.|2\.([0-5]\.|6\.STABLE([0-9][^0-9]*|1[0-7][^0-9]*)$))"
  )
  {
    report = string(
      "\n",
      "The remote Squid proxy returned the following banner :\n",
      "\n",
      "  ", banner, "\n",
      "\n",
      "Note that Nessus has not actually attempted to exploit this issue so\n",
      "it may be a false-positive.\n"
    );
    security_warning(port:port, extra:report);
  }

