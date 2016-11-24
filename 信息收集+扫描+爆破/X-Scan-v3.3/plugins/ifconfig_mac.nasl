#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33276);
  script_version("$Revision: 1.5 $");

  script_name(english:"Enumerate MAC Addresses via SSH");
  script_summary(english:"Uses the result of ifconfig -a");

 script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates MAC addresses on a remote host." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host via SSH with the supplied
credentials, this plugin enumerates MAC addresses." );
 script_set_attribute(attribute:"solution", value:
"Disable any unused interfaces." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/ifconfig");

  exit(0);
}


include("global_settings.inc");


ifconfig = get_kb_item("Host/ifconfig");
if (isnull(ifconfig)) exit(0);


pat_dev = "^([a-z]+[a-z0-9]+(:[0-9]+)?)[: ].*";
pat_mac = ".*(HWaddr|ether) ?([0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}).*";


# Gather information.
dev = NULL;
devs = make_array();

foreach line (split(ifconfig, keep:FALSE))
{
  if (line =~ "^([a-z]+[a-z0-9]+(:[0-9]+)?)[: ].*")
  {
    dev = ereg_replace(pattern:pat_dev, replace:"\1", string:line);
    if (dev == line) dev = NULL;
  }
  if ("HWaddr " >< line || "ether " >< line)
  {
    mac = ereg_replace(pattern:pat_mac, replace:"\2", string:line);
    if (mac != line && dev)
    {
      if (devs[mac]) devs[mac] += ' & ' + dev;
      else devs[mac] = dev;
    }
  }
}
if (max_index(keys(devs)) == 0) exit(0);


# Issue report.
info = "";

foreach mac (keys(devs))
{
  if (' & ' >< devs[mac]) s = "s";
  else s = "";

  info += '  - ' + mac + ' (interface' + s + ' ' + devs[mac] + ')\n';
}

if (report_verbosity > 0 && info)
{
  if (max_index(keys(devs)) == 1) report = "address exists";
  else report = "addresses exist";
  report = string(
    "\n",
    "The following MAC ", report, " on the remote host :\n",
    "\n",
    info
  );
  security_note(port:0, extra:report);
}
else security_note(0);
