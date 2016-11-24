#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21747);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-3601");
  script_bugtraq_id(18522);
  script_xref(name:"OSVDB", value:"41851");

  script_name(english:"BDPDT for DotNetNuke (.net nuke) uploadfilepopup.aspx File Upload Privilege Escalation");
  script_summary(english:"Checks for BDPDT's uploadfilepopup.aspx");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that allows uploading of
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The remote host contains BDPDT, a database abstraction layer used in
various add-on modules for DotNetNuke. 

The installed version of the BDPDT contains an ASP.NET script that
allows an unauthenticated attacker to gain control of the affected
host by allowing uploading arbitrary files with the
'UploadFilePopUp.aspx' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.dotnetnuke.com/Community/Blogs/tabid/825/EntryID/422/Default.aspx" );
 script_set_attribute(attribute:"see_also", value:"http://forums.asp.net/thread/1276672.aspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.wwwcoder.com/Default.aspx?tabid=283&EntryID=723" );
 script_set_attribute(attribute:"see_also", value:"http://www.wwwcoder.com/Default.aspx?tabid=283&EntryID=733" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a newer version of BDPDT." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);

# Check if the affected script exists.
script = "/DesktopModules/BDPDT/uploadfilepopup.aspx";
foreach dir (cgi_dirs())
{
  r = http_send_recv3(method: "GET", item:string(dir, script), port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if it does.
  if (
    '<input name="cmdBrowse"' >< res &&
    '<a id="btnUploadFile"' >< res &&
    '<input type="hidden" name="__VIEWSTATE"' >< res
  )
  {
    report = string(
      "Nessus found the affected script available via the affected URL :\n",
      "\n",
      "  ", dir, script, "\n"
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
