#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35710);
 script_version("$Revision: 1.2 $");

 script_name(english: "Internet Gateway Device WAN Interface UPnP Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote IGD router can be configured on its WAN interface.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to add 'port mappings' by sending SOAP request to its
external interface.");
 script_set_attribute(attribute:"solution", value:"Restrict external access to this device.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_end_attributes();

 script_summary(english: "reconfigure IGD router from outside");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("upnp_add_port_mapping.nasl", "upnp_external_ip_addr.nasl");
 script_require_keys("upnp/igd_add_port_mapping");
 exit(0);
}

include('global_settings.inc');
include('network_func.inc');

if (! get_kb_item('upnp/igd_add_port_mapping')) exit(0);
extip = get_kb_item('upnp/external_ip_addr');
if (! isnull(extip))
{
  if (get_host_ip() == extip)
    security_warning(0);
}
else
{
 if (! is_private_addr() && ! islocalnet())
   security_warning(0, extra: "
** Nessus relied on the fact that this is a public address.
** If the internal address of this router is public, disregard this alert.
");
}

