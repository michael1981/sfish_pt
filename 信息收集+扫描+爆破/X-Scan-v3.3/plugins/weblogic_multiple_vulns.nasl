#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14722);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2320");
 script_bugtraq_id(11168);
 script_xref(name:"OSVDB", value:"9978");
 
 script_name(english:"WebLogic < 8.1 SP3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is BEA WebLogic version
8.1 SP2 or older.  There are multiple vulnerabilities in such versions
that may allow unauthorized access on the remote host or to get the
content of the remote JSP scripts." );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-65.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-66.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-67.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-68.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-69.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-70.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-71.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-72.00.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-73.00.jsp" );
 script_set_attribute(attribute:"solution", value:
"Apply Service Pack 3 on WebLogic 8.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks the version of WebLogic");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner || "WebLogic " >!< banner) exit(0);

pat = "^Server:.*WebLogic .*([0-9]+\.[0-9.]+) ";
matches = egrep(pattern:pat, string:banner);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      # Extract the version and service pack numbers.
      nums = split(ver[1], sep:".", keep:FALSE);
      ver_maj = int(nums[0]);
      ver_min = int(nums[1]);

      sp = ereg_replace(
        string:match, 
        pattern:".* (Service Pack |SP)([0-9]+) .+",
        replace:"\2"
      );
      if (!sp) sp = 0;
      else sp = int(sp);

      # Check them against vulnerable versions listed in BEA's advisories.
      if (
        # version 6.x
        (
          ver_maj == 6 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 6)
          )
        ) ||

        # version 7.x
        (ver_maj == 7 && (ver_min == 0 && sp <= 5)) ||
  
        # version 8.x
        (
          ver_maj == 8 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 2)
          )
        )
      ) {
        security_hole(port);
      }
      exit(0);
    }
  }
}
