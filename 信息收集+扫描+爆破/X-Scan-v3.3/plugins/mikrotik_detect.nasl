#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30212);
  script_version("$Revision: 1.7 $");

  script_name(english:"MikroTik RouterOS Detection");
  script_summary(english:"Examines various banners");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a router." );
 script_set_attribute(attribute:"description", value:
"According to one of its service banners, the remote host is running
MikroTik RouterOS, a specialized Linux-based operating system that
allows Intel-class PCs to act as a network router / access point." );
 script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/ftp", 21, "Services/ssh", 22, "Services/telnet", 23, "Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("ssh_func.inc");
include("telnet_func.inc");


# Use a service banner to fingerprint it as running RouterOS,
# and get its version if possible.
service = NULL;
ver = NULL;
#
# - FTP.
if (isnull(service))
{
  ports = get_kb_list("Services/ftp");
  if (isnull(ports)) ports = make_list(21);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_ftp_banner(port:port);
      if (banner && "MikroTik FTP" >< banner)
      {
        pat = "^[0-9]{3} .+ FTP server \(MikroTik ([^\)]+)\) ready";
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
              service = "FTP";
              break;
            }
          }
        }
      }
      if (service) break;
      if (isnull(service) && !thorough_tests) exit(0);
    }
  }
}
# - Telnet.
if (isnull(service))
{
  ports = get_kb_list("Services/telnet");
  if (isnull(ports)) ports = make_list(23);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_telnet_banner(port:port);
      if (banner && "MikroTik v" >< banner)
      {
        pat = "^MikroTik v([0-9].+)$";
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
              service = "Telnet";
              break;
            }
          }
        }
      }
      if (service) break;
      if (isnull(service) && !thorough_tests) exit(0);
    }
  }
}
# - HTTP.
if (isnull(service))
{
  ports = get_kb_list("Services/www");
  if (isnull(ports)) ports = make_list(80);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      res = http_get_cache(item:"/", port:port);
      if (res && ">mikrotik routeros" >< res)
      {
        pat = ">mikrotik routeros (.+) configuration page<";
        matches = egrep(pattern:pat, string:res);
        if (matches)
        {
          set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

          foreach match (split(matches))
          {
            match = chomp(match);
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              service = "HTTP";
              break;
            }
          }
        }
      }
      if (service) break;
      if (isnull(service) && !thorough_tests) exit(0);
    }
  }
}
# - SSH.
#
# nb: keep this towards the end as it doesn't offer up the version of RouterOS.
if (isnull(service))
{
  ports = get_kb_list("Services/ssh");
  if (isnull(ports)) ports = make_list(22);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      soc = open_sock_tcp(port);
      if (soc)
      {
        banner = recv_line(socket:soc, length:4096);
        if (banner && ereg(pattern:"^SSH-.+_Mikrotik_v", string:banner))
          service = "SSH";
        close(soc);

        if (service) break;
        if (isnull(service) && !thorough_tests) exit(0);
      }
    }
  }
}


if (service)
{
  if (ver) set_kb_item(name:"MikroTik/Version", value:ver);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "According to its ", service, " banner, the remote host is running MikroTik\n",
      "RouterOS"
    );
    if (ver) report += ' version ' + ver;
    report += '.';
    security_note(port:0, extra:report);
  }
  else security_note(port:0, extra:report);
}
