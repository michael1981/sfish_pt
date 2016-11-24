#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39354);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2636");
  script_bugtraq_id(35264);
  script_xref(name:"OSVDB", value:"54928");
  script_xref(name:"Secunia", value:"35392");

  script_name(english:"Kerio MailServer < 6.6.2 Patch 3 / 6.7.0 Patch 1 XSS (KSEC-2009-06-08-01)");
  script_summary(english:"Checks version in banners");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by a cross-site scripting issue.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Kerio MailServer prior to 6.6.2 Patch 3 or 6.7.0 Patch 1.  The webmail
component of such versions is reportedly affected by a cross-site
scripting vulnerability on the Integration page. 

Successful exploitation of this issue could lead to execution of
arbitrary HTML and script code in a user's browser within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/support/security-advisories#0906" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.6.2 Patch 3 / 6.7.0 Patch 1 or later.");
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "http_version.nasl","popserver_detect.nasl","nntpserver_detect.nasl","find_service_3digits.nasl");
  if (NASL_LEVEL >= 3000)
  script_require_ports("Services/www", 80, "Services/smtp", 25, "Services/pop3", 110, "Services/nntp", 119, "Services/imap", 143);

  exit(0);
}

include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("http.inc");


# Unless we are paranoid,
# exit if webmail is not running.

if(report_paranoia < 2)
{
 p = get_http_port(default:80);

 res = http_send_recv3(method:"GET", item:"/webmail/login.php", port:p);
 if (isnull(res)) exit(0);
 if(!ereg(pattern:">Kerio MailServer .+ WebMail</", string:res[2])) exit(0);
}

# Try to get the version number from a banner.

ver = NULL;
service = NULL;

# - SMTP.
if (isnull(ver))
{
  ports = get_kb_list("Services/smtp");
  if (isnull(ports)) ports = make_list(25);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_smtp_banner(port:port);
      if (banner && " Kerio MailServer " >< banner)
      {
        pat = " Kerio MailServer ([0-9][0-9.]+[a-zA-Z0-9 ]*) ESMTP";
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
    }
    if (!isnull(ver)) break;
  }
}

# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_pop3_banner(port:port);
      if (banner && " Kerio MailServer " >< banner)
      {
        pat = "^\+OK .*Kerio MailServer ([0-9][0-9.]+[a-zA-Z0-9 ]*) POP3";
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
    }
    if (!isnull(ver)) break;
  }
}

# - IMAP.
if (isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_imap_banner(port:port);
      if (banner && " Kerio MailServer " >< banner)
      {
        pat = "^\* OK Kerio MailServer ([0-9][0-9.]+[a-zA-Z0-9 ]*) IMAP";
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
    }
    if (!isnull(ver)) break;
  }
}

# - NNTP.
if (isnull(ver))
{
  ports = get_kb_list("Services/nntp");
  if (isnull(ports)) ports = make_list(119);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_unknown_banner(port:port);
      if (banner && " Kerio MailServer " >< banner)
      {
        pat = "^200 Kerio MailServer ([0-9][0-9.]+[a-zA-Z0-9 ]*) NNTP";
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
              service = "NNTP";
              break;
            }
          }
        }
      }
    }
    if (!isnull(ver)) break;
  }
}

# There's a problem if the version is < 6.6.2 patch 3 or 6.7.0 patch 1

if (ver)
{
  if (ereg(pattern:"^(6\.6\.([0-1]|2($|[^0-9 ])|2 patch [0-2]($|[^0-9])))",string:ver) ||
      ereg(pattern:"^(6\.7\.(0($|[^0-9 ])|0 patch 0($|[^0-9])))",string:ver))
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "According to its ", service, " banner, the remote host is running Kerio\n",
        "MailServer version ", ver, ".\n"
       );
       security_warning(port:port, extra:report);
     }
      else security_warning(port);
  }
}
