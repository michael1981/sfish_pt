#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20094);
 script_version ("$Revision: 1.19 $");
 
 script_name(english:"VMware Virtual Machine Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be a VMware virtual machine." );
 script_set_attribute(attribute:"description", value:
"According to the MAC address of its network adapter, the remote host
is a VMware virtual machine. 

Since it is physically accessible through the network, ensure that its
configuration matches your organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english:"Determines if the remote host is VMware");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencies("netbios_name_get.nasl", "ssh_get_info.nasl", "snmp_ifaces.nasl", "bad_vlan.nasl");
 exit(0);
}

ether = get_kb_item("SMB/mac_addr");
if (! ether) 
{
  if ( islocalnet() ) ether = get_kb_item("ARP/mac_addr");

  if ( ! ether )
  {
   buf = get_kb_item("Host/ifconfig");
   if ( buf ) 
    {
    array = split(buf, sep:'\n', keep:FALSE);
    for (  i = 0 ; i < max_index(array); i ++ )
    {
     if ( array[i] =~ "^[a-z]+[0-9]: ")
	current_iface = ereg_replace(pattern:"([a-z]+[0-9]): .*", string:array[i], replace:"\1");
 
     if ( array[i] =~ "(ether|hwaddr) ([0-9a-f]+:){5}[0-9a-f]+" && array[i] !~ "^vmnet[0-9]" && ( current_iface == NULL || current_iface !~ "^vmnet[0-9]") )
	{
	   ether += tolower(ereg_replace(pattern:".*(hwaddr|ether) ([0-9a-f:]+).*", replace:"\2", string:array[i], icase:TRUE)) + '\n';
	}
     }
    }
  }

  if ( ! ether )
  {
    i = 0;
    while ( TRUE )
     {
	 str = get_kb_item("SNMP/ifPhysAddress/" + i );
	 if ( str ) ether += str + '\n';
	 else break;
	 i ++;
     }
  }
}
if ( ! ether ) exit(0);
set_kb_item(name: "Host/mac_addrs", value: ether);
# -> http://standards.ieee.org/regauth/oui/index.shtml
if ( egrep(pattern:"^00:(0c:29|05:69|50:56)", string:ether, icase:TRUE) ) security_note(0);
