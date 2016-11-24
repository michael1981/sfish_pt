#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35351);
 script_version ("$Revision: 1.3 $");
 script_name(english: "System Information Enumeration (via DMI)");
 
 script_set_attribute(attribute:"synopsis", value:
"Information about the remote system's hardware can be read." );
 script_set_attribute(attribute:"description", value:
"Using the SMBIOS (aka DMI) interface, it was possible to retrieve
information about the remote system's hardware, such as its product
name and serial number." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english: "Extract system information from dmidecode");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "General");
 script_dependencies("bios_get_info_ssh.nasl");
 script_require_keys("Host/dmidecode");
 exit(0);
}


buf = get_kb_item("Host/dmidecode");
if ("System Information" >!< buf) exit(0);

keys = make_list("Product Name", "Serial Number");
values = make_list();
found = 0;

lines = split(buf, keep: 0);
drop_flag = 1;
foreach l (lines)
{
  if (ereg(string: l, pattern: '^System Information'))
  {
   drop_flag = 0;
   continue;
  }
  else if (ereg(string: l, pattern: '^[A-Z]')) drop_flag = 1; 
  if (drop_flag) continue;
  foreach k (keys)
  {
    pat = strcat('^[ \t]+', k, '[ \t]*:[  \t]*([^ \t].*)');
    v = eregmatch(string: l, pattern: pat);
    if (! isnull(v)) { values[k] = v[1]; found ++; }
  }
} 

if (! found) exit(0);

report = "";
foreach k (keys(values))
{
 k2 = str_replace(string: k, find: " ", replace: "");
 set_kb_item(name: strcat("DMI/System/", k2), value: values[k]);
 report = strcat( report, k, 
 	  	  crap(data: ' ', length: 13 - strlen(k)), ' : ', values[k], '\n');
}

security_note(port: 0, extra: report);
