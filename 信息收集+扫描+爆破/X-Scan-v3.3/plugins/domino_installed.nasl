#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27855);
  script_version("$Revision: 1.5 $");

  script_name(english:"IBM Lotus Domino Detection");

  script_summary(english:"Checks for Lotus Domino");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running Lotus Domino." );
 script_set_attribute(attribute:"description", value:
"Lotus Domino, an enterprise application for collaborative messaging,
scheduling, directory services, and web services, is running on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www-306.ibm.com/software/lotus/products/domino/" );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl", "ldap_search.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, "Services/ldap", 389);

  exit(0);
}


include("global_settings.inc");
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
    if (banner && " Service (Lotus Domino Release " >< banner)
    {
      pat = " Service \(Lotus Domino Release ([0-9][^)]+)\)";
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
    if (banner && " Lotus Notes POP3 " >< banner)
    {
      pat = " Lotus Notes POP3 server version Release ([0-9][^ ]+) ready";
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
    if (banner && " Domino IMAP4 " >< banner)
    {
      pat = " Domino IMAP4 Server Release ([0-9][^ ]+) ready";
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
# - LDAP.
if (isnull(ver))
{
  port = get_kb_item("Services/ldap");
  if (!port) port = 389;
  if (get_port_state(port))
  {
    vendorname = get_kb_item("LDAP/"+port+"/vendorName");
    vendorversion = get_kb_item("LDAP/"+port+"/vendorVersion");
    if (
      vendorname && "IBM Lotus" >< vendorname &&
      vendorversion && "Release " >< vendorversion
    ) 
    {
      service = "LDAP";
      ver = strstr(vendorversion, "Release ") - "Release ";
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}


# Issue a report if it was found on the remote.
if (ver && service)
{
  if ("FP" >< ver) ver = str_replace(find:"FP", replace:" FP", string:ver);

  set_kb_item(name:string("Domino/Version"), value:ver);

  if (service == "LDAP")
    note = string(
      "Based on the response to an LDAP request, Lotus Domino version ", ver, "\n",
      "appears to be running on the remote host.\n"
    );
  else 
  {
    note = string(
      "According to its ", service, " banner, Lotus Domino version ", ver, " appears\n",
      "to be running on the remote host.\n"
    );
  }

  security_note(port:0, extra: note);
}
