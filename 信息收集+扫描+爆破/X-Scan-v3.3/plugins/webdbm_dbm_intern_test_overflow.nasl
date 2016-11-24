#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25681);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-3614");
  script_bugtraq_id(24773);
  script_xref(name:"OSVDB", value:"37838");

  script_name(english:"SAP DB / MaxDB Web Server DBM_INTERN_TEST Event Buffer Overflow");
  script_summary(english:"Checks version of Web DBM");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SAP DB or MaxDB, a SAP-certified open-
source database supporting OLTP and OLAP. 

According to its version, the Web DBM component of SAP DB or MaxDB on
the remote host reportedly contains a stack-based buffer overflow
triggered when displaying user-supplied arguments as part of the
'DBM_INTERN_TEST' event.  By sending an HTTP request with an argument
- a cookie for example - exceeding 10,000 bytes, an unauthenticated
remote attacker can leverage this issue to execute arbitrary code on
the affected host subject to the privileges of the 'wahttp' process. 

Note that on Windows the 'wahttp' process runs with 'SYSTEM'
privileges so a successful attack may result in a complete compromise
of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472891/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/maxdb/changes/changes_7.5.00.44.html#Web_DBM" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/maxdb/changes/changes_7.6.00.37.html#Web_DBM" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MaxDB version 7.5.00.44 / 7.6.00.37 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9999);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:9999);


# Make sure the banner indicates it's Web DBM.
banner = get_http_banner(port:port);
if (!banner || "Server: SAP-Internet-SapDb-Server" >!< banner) exit(0);


# Get the version number.
r = http_send_recv3(method: "GET", item:"/webdbm?Page=VERSION", port:port);
if (isnull(r)) exit(0);

ver = NULL;
build = NULL;
pat = '<td class="(dbmSTbvCellStd|dbmSTbvCellLast|table[0-9]).*>(&nbsp;)*([0-9][0-9.-]+) *(&nbsp;)*</';
matches = egrep(pattern:pat, string:r[2]);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    m = eregmatch(pattern:pat, string:match);
    if (!isnull(m))
    {
      if ("table" >< m[1] && m[3] !~ "^[0-9]{3}-") ver = chomp(m[3]);
      if ("CellStd" >< m[1]) ver = chomp(m[3]);
      if ("CellLast" >< m[1] || ("table" >< m[1] && m[3] =~ "^[0-9]{3}-"))
      {
        build = m[3];
        if (build =~ "^([0-9][0-9][0-9])-.*")
        {
          build = ereg_replace(pattern:"^([0-9][0-9][0-9])-.*", replace:"\1", string:build);
          build = int(build);
        }
      }
    }
  }
}
if (isnull(ver)) exit(0);
if (!isnull(build)) ver += "." + build;


# There's a problem if the version is under 7.5.0.44 / 7.6.00.37.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 7 ||
  (
    int(iver[0]) == 7 &&
    (
      int(iver[1]) < 5 ||
      (int(iver[1]) == 5 && int(iver[2]) == 0 && !isnull(iver[3]) && int(iver[3]) < 44) ||
      (int(iver[1]) == 6 && int(iver[2]) == 0 && !isnull(iver[3]) && int(iver[3]) < 37)
    )
  )
)
{
  report = string(
    "According to its banner, MaxDB / SAP DB version ", ver, " is installed\n",
    "on the remote host.\n"
  );
  security_hole(port:port, extra:report);
}
