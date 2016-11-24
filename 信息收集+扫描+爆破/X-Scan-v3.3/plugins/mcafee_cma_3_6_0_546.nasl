#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25702);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5271", "CVE-2006-5272", "CVE-2006-5273", "CVE-2006-5274");
  script_bugtraq_id(24863);
  script_xref(name:"OSVDB", value:"36098");
  script_xref(name:"OSVDB", value:"36099");
  script_xref(name:"OSVDB", value:"36100");
  script_xref(name:"OSVDB", value:"36101");

  script_name(english:"McAfee Common Management Agent 3.6.0.546 Multiple Vulnerabilities");
  script_summary(english:"Checks version of McAfee CMA");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilties." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee. 

The Common Management Agent on the remote host contains several memory
corruption issues due to improper bounds checking.  Provided the agent
is operating in Managed mode, an unauthenticated remote attacker may
be able to exploit these issues to crash the agent, corrupt memory, or
even execute arbitrary code remotely with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/threats/269.html" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/761/613364_f.SAL_Public.html" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/762/613365_f.SAL_Public.html" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/763/613366_f.SAL_Public.html" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/764/613367_f.SAL_Public.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Common Management Agent 3.6.0 Patch 1 (3.6.0.546) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


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
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }
}
if (isnull(ver)) exit(0);


# There's a problem if the version is under 3.6.0.546.
#
# nb: the version reported is the same as the file version of
#     "Common Framework\FrakeworkService.exe", which is what matters.
iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 3 ||
  (
    iver[0] == 3 &&
    (
      iver[1] < 6 ||
      (iver[1] == 6 && iver[2] == 0 && iver[3] < 546)
    )
  )
)
{
  report = string(
    "\n",
    "According to its banner, McAfee Common Management Agent version \n",
    ver, " is installed on the remote host."
  );
  security_hole(port:port, extra:report);
}
