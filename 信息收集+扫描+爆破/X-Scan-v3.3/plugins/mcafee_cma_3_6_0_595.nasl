#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31732);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1357");
  script_bugtraq_id(28228);
  script_xref(name:"OSVDB", value:"42853");
  script_xref(name:"Secunia", value:"29337");

  script_name(english:"McAfee Common Management Agent 3.6.0 UDP Packet Handling Format String");
  script_summary(english:"Checks version of McAfee CMA");

 script_set_attribute(attribute:"synopsis", value:
"A remote service may be affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee. 

The version of the Common Management Agent on the remote host is
earlier than 3.6.0.595 and, as such, contains a format string
vulnerability.  If configured with a debug level of 8, its highest
level and not the default, an unauthenticated remote attacker may be
able to leverage this issue by sending a specially-crafted UDP packet
to the agent broadcast port to crash the service or even execute
arbitrary code on the affected host. 

Note that Nessus has not looked at the setting of the LogLevel, only
the version number in the agent's banner, so it may not actually be
vulnerable to attack." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/meccaffi-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/489476/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/234/615103_f.SAL_Public.html" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix BZ398370 Build 595 for Common Management Agent 3.6.0
Patch 3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: only run the check if reporting is paranoid since we
#     can't determine the log level setting remotely.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:8081);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# Get CMA's version.
ver = NULL;

if ('href="FrameworkLog.xsl"' >< res && "<ePOServerName>" >< res)
{
  # Extract the version number.
  pat = "<version>([^<]+)</ver";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        break;
      }
    }
  }
}
if (isnull(ver)) exit(0);


# There's a problem if the version is under 3.6.0.595.
iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix = split("3.6.0.595", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its banner, the remote is running McAfee Common\n",
        "Management Agent version ", ver, ".\n"
      );
      security_warning(port:0, extra:report);
    }
    else security_warning(0);

    break;
  }

