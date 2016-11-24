#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(41028);
 script_version("$Revision: 1.1 $");

 script_cve_id("CVE-1999-0517");
 script_bugtraq_id(2112);
 script_xref(name:"OSVDB", value:"209");

 script_name(english:"SNMP Agent Default Community Name (public)");
 script_summary(english:"Checks if the SNMP Agent supports the community name 'public'");

 script_set_attribute(
  attribute:"synopsis",
  value:"The community name of the remote SNMP server can be guessed."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "It is possible to obtain the default community name of the remote\n",
   "SNMP server.\n",
   "\n",
   "An attacker may use this information to gain more knowledge about the\n",
   "remote host, or to change the configuration of the remote system (if\n",
   "the default community allow such modifications)."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Disable the SNMP service on the remote host if you do not use it,\n",
   "filter incoming UDP packets going to this port, or change the default\n",
   "community string."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/25"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SNMP");

 script_dependencies("snmp_default_communities.nasl");
 script_require_keys("SNMP/default/community");
 exit(0);
}


port = get_kb_item("SNMP/port");
if (!port) port = 161;


default = get_kb_list("SNMP/default/community");
if (isnull(default)) exit(0, "The 'SNMP/default/community' KB item is missing.");
if (max_index(default) > 1) exit(0, max_index(default)+" default communities were found.");

comm_list = strcat('  - ', default[0], '\n');
if ("public" >< comm_list)
{
  report = string(
    "\n",
    "The remote SNMP server replies to the following default community\n",
    "string :\n",
    "\n",
    comm_list
  );
  security_warning(port:port, extra:report, protocol:"udp");
}
else exit(0, "The default SNMP community is '"+comm_list+"' rather than 'public'.");
