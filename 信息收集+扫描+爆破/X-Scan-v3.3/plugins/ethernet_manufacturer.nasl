#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35716);
 script_version ("$Revision: 1.4 $");

 script_name(english: "Ethernet card brand");
 script_set_attribute(attribute: "synopsis", value: 
"The manufacturer can be deduced from the Ethernet OUI.");
 script_set_attribute(attribute: "description", value: 
"Each ethernet MAC address starts with a 24-bit 'Organizationally 
Unique Identifier'.
These OUI are registered by IEEE.");
 script_set_attribute(attribute: "see_also", value: "http://standards.ieee.org/faqs/OUI.html");
 script_set_attribute(attribute: "see_also", value: "http://standards.ieee.org/regauth/oui/index.shtml");
 script_set_attribute(attribute: "solution", value: "n/a");
 script_set_attribute(attribute: "risk_factor", value: "None");
 script_end_attributes();

 script_summary(english: "Deduce the Ethernet brand from the OUI");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencies("vmware_detect.nasl");
 exit(0);
}

function my_cmp(a, b)
{
  a = substr(a, 0, 6);
  if (a == b) return 0;
  if (a < b) return -1;
  return 1;
}

function my_bsearch(v, e)
{
  local_var	n, i, i1, i2, c;

  n = max_index(v);
  i1 = 0; i2 = n;
  while (i1 < i2)
  {
    i = (i1 + i2) / 2;
    c = my_cmp(a: v[i], b: e);
    if (c == 0) return v[i];
    if (c < 0) i1 = i+1;
    else i2 = i;
  }
  return NULL;
}

ether_list = get_kb_item("Host/mac_addrs");
if (isnull(ether_list)) exit(0);

include("oui.inc");

oui_lines = split(oui, keep: 0);
oui = NULL;	# Free memory
oui_lines = sort(oui_lines);	# Prepare for binary search
report = '';

foreach ether (split(ether_list, keep:FALSE))
{
  e = ereg_replace(string: ether, pattern: "^(..):(..):(..):.*", replace: "\1\2\3 ");
  e = toupper(e);
  line = my_bsearch(v: oui_lines, e: e);
  if (line)
  {
    maker = chomp(substr(line, 7));
    report = strcat(report, ether, ' : ', maker, '\n');
    set_kb_item(name: "Host/ethernet_manufacturer", value: maker);
  }
}

if (report)
{
 security_note(port: 0, extra: '\nThe following card manufacturers were identified :\n\n'+report);
}
