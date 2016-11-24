#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31119);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0858", "CVE-2008-0859", "CVE-2008-0860");
  script_bugtraq_id(27868);
  script_xref(name:"OSVDB", value:"42124");
  script_xref(name:"OSVDB", value:"42125");
  script_xref(name:"OSVDB", value:"42126");
  script_xref(name:"Secunia", value:"29021");

  script_name(english:"Kerio MailServer < 6.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of KMS services");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

According to its banner, the installed version of Kerio MailServer is
affected by several issues :

  - There is a possible buffer overflow in the Visnetic
    anti-virus plug-in.

  - There is an as-yet unspecified security issue with NULL
    DACL in the AVG plug-in.

  - Memory corruption is possible during uudecode decoding." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.5.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  if (NASL_LEVEL >= 3000)
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
    if (!isnull(ver)) break;
  }
}


# There's a problem if the version is < 6.5.0.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("6.5.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "According to its ", service, " banner, the remote host is running Kerio\n",
          "MailServer version ", ver, ".\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
