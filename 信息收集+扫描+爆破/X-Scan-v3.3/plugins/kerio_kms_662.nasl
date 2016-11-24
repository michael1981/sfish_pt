#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35258);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-5760", "CVE-2008-5769");
  script_bugtraq_id(32863);
  script_xref(name:"Secunia", value:"32955");
  script_xref(name:"OSVDB", value:"50788");
  script_xref(name:"OSVDB", value:"50789");
  script_xref(name:"OSVDB", value:"50790");

  script_name(english:"Kerio MailServer < 6.6.2 Multiple XSS (KSEC-2008-12-16-01)");
  script_summary(english:"Checks for Kerio MailServer < 6.6.2");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by several cross-site scripting
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.6.2.  Multiple files in such versions are
reportedly affected by cross-site scripting vulnerabilities. 

  - The application fails to sanitize input to the parameter
    'folder' of the 'mailCompose.php' script as well as the 
    parameter 'daytime' of the 'calendarEdit.php' script
    before using it to generate dynamic HTML.

  - Content passed to 'sent' parameter of the 'error413.php'
    script is not sanitized before being returned to the 
    user.

Successful exploitation of these issues could lead to execution of
arbitrary HTML and script code in a user's browser within the security
context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/security_advisory.html#0812" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
        pat = " Kerio MailServer ([0-9][0-9.]+) ESMTP";
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
        pat = "^\+OK .*Kerio MailServer ([0-9][0-9.]+) POP3";
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
        pat = "^\* OK Kerio MailServer ([0-9][0-9.]+) IMAP";
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
        pat = "^200 Kerio MailServer ([0-9][0-9.]+) NNTP";
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

# There's a problem if the version is < 6.6.2
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("6.6.2", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	
      if (report_verbosity)
      {
        report = string(
          "\n",
          "According to its ", service, " banner, the remote host is running Kerio\n",
          "MailServer version ", ver, ".\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
