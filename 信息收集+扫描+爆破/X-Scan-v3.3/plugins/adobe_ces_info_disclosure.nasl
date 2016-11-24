#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26021);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4651");
  script_bugtraq_id(25640);
  script_xref(name:"OSVDB", value:"38055");

  script_name(english:"Adobe Connect Enterprise Server Information Disclosure");
  script_summary(english:"Checks version number of Adobe Connect Enterprise Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Connect Enterprise Server installed on the remote
host allows non-admins to view but not alter certain administrator-
only pages." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-14.html" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to Adobe Connect 6 Service Pack 3 or apply the patch
for Adobe Connect 6 Service Pack 2 referenced in the vendor advisory
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Make sure it's Adobe Connect Enterprise Server.
r = http_send_recv3(method:"GET", port:port, item:"/system/login");
if (isnull(r)) exit(0);
res = r[2];

if ("<title>Adobe Connect Enterprise" >< res)
{
  # Extract version / release info.
  r = http_send_recv3(method:"GET", item:"/version.txt", port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  line1 = res - strstr(res, '\n');
  pat = "^([0-9]+\.[0-9]+),([0-9]+)$";
  items = eregmatch(pattern:pat, string:line1);
  if (!isnull(items))
  {
    ver = items[1];
    release = int(items[2]);

    # There's a problem if...
    if (
      # it's version 6.1 or older or...
      ver =~ "^([0-5]\.|6\.[01]$)" ||
      # it's version 6.2 and a release before 389 or...
      (ver == "6.2" && release < 389) ||
      # it's version 6.2 release 389 or 390 and no fix for bug #1568340
      (
        ver == "6.2" && 
        (release == 389 || release == 390) && 
        "fix for 1568340" >!< res
      )
    ) security_warning(port);
  }
}
