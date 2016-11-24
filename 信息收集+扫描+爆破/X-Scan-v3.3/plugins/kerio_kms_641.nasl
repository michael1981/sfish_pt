#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25991);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-3993");
  script_bugtraq_id(25038);
  script_xref(name:"OSVDB", value:"38571");

  script_name(english:"Kerio MailServer < 6.4.1 Attachment Filter Unspecified Vulnerability");
  script_summary(english:"Checks version of KMS SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an unspecified vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

According to its banner, the installed version of Kerio MailServer
contains an unspecified vulnerability involving the attachment filter." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.4.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/nntp", 119, "Services/imap", 143);

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
#
# - SMTP.
if (isnull(ver))
{
  port = get_kb_item("Services/smtp");
  if (!port) port = 25;
  if (get_port_state(port))
  {
    banner = get_smtp_banner(port:port);
    if (banner && " Kerio MailServer " >< banner)
    {
      pat = " Kerio MailServer ([0-9][0-9.]+) ESMTP ";
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
    if (banner && " Kerio MailServer " >< banner)
    {
      pat = " Kerio MailServer ([0-9][0-9.]+) POP3";
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
# - NNTP.
if (isnull(ver))
{
  port = get_kb_item("Services/nntp");
  if (!port) port = 119;
  if (get_port_state(port))
  {
    banner = get_unknown_banner(port:port);
    if (banner && " Kerio MailServer " >< banner)
    {
      pat = " Kerio MailServer ([0-9][0-9.]+) NNTP ";
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
    if (banner && " Kerio MailServer " >< banner)
    {
      pat = " Kerio MailServer ([0-9][0-9.]+) IMAP";
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


# There's a problem if the version is < 6.4.1.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("6.4.1", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      report = string(
        "According to its ", service, " banner, the remote is running Kerio MailServer\n",
        "version ", ver, "."
      );
      security_hole(port:port, extra:report);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
