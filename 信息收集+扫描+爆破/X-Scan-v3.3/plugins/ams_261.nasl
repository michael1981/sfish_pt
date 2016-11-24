#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28289);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-6101");
  script_bugtraq_id(26514);
  script_xref(name:"OSVDB", value:"42399");
  script_xref(name:"OSVDB", value:"42400");

  script_name(english:"Ability Mail Server < 2.61 Multiple Remote DoS");
  script_summary(english:"Checks versions of AMS services");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by denial of service
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ability Mail Server. 

According to its banner, the installed version of Ability Mail Server
is affected by two issues that could cause the application to crash. 
One involves messages that are changed to a blank string, the other
IMAP4 commands with malformed number list ranges. 

It is believed that exploitation of either issue requires
authentication." );
 script_set_attribute(attribute:"see_also", value:"http://www.code-crafters.com/abilitymailserver/updatelog.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ability Mail Server version 2.61 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, "Services/www", 8000, 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Try to get the version number from a banner.
ver = NULL;
service = NULL;
#
# - SMTP.
if (isnull(ver))
{
  port = get_kb_item("Services/smtp");
  if (!port) port = 25;
  if (get_port_state(port))
  {
    banner = get_smtp_banner(port:port);
    if (banner && "Code-Crafters Ability Mail Server " >< banner)
    {
      pat = " ESMTP \(Code-Crafters Ability Mail Server ([0-9][0-9.]+)\)";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "SMTP";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - POP3
if (isnull(ver))
{
  port = get_kb_item("Services/pop3");
  if (!port) port = 110;
  if (get_port_state(port))
  {
    banner = get_pop3_banner(port:port);
    if (banner && " Code-Crafters Ability Mail Server " >< banner)
    {
      pat = "with Code-Crafters Ability Mail Server ([0-9][0-9.]+) <";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "POP3";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - IMAP.
if (isnull(ver))
{
  port = get_kb_item("Services/imap");
  if (!port) port = 143;
  if (get_port_state(port))
  {
    banner = get_imap_banner(port:port);
    if (banner && " Code-Crafters Ability Mail Server " >< banner)
    {
      pat = ", with Code-Crafters Ability Mail Server ([0-9][0-9.]+)\.";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "IMAP";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - Web servers.
if (isnull(ver))
{
  port = get_http_port(default:8000);
  # get_http_port will exit if there is no web server, but this is not a problem
  # considering the structure of this script

    # nb: get_http_banner() doesn't work on the webmail port.
    if (port == 8000)
    {
      banner = "";
      r = http_send_recv3(method:"GET", item:"/_index", port:port);
      if (! isnull(r)) banner = strcat(r[0], r[1]);
    }
    else banner = get_http_banner(port:port);
    if (banner && " Code-Crafters Ability Mail Server " >< banner)
    {
      pat = "^Server: Code-Crafters Ability Mail Server ([0-9][0-9.]+)";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "HTTP (port " + port + ")";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
}


# There's a problem if the version is < 2.61.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("2.61", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      report = string(
        "\n",
        "According to its ", service, " banner, the remote is running Ability Mail\n",
        "Server version ", ver, "."
      );
      security_warning(port:port, extra:report);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
