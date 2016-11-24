#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include( 'compat.inc' );

if(description)
{
  script_id(19762);
  script_version ("$Revision: 1.9 $");

  script_name(english:"SNMP settings");
  script_summary(english:"Sets SNMP settings");

  script_set_attribute(
    attribute:'synopsis',
    value:'Sets SNMP settings.'
  );

  script_set_attribute(
    attribute:'description',
    value:string(
      "This script just sets global variables (SNMP community string and SNMP\n",
      "port) and does not perform any security check."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_category(ACT_GATHER_INFO);

  script_add_preference(name: "Community name :", type: "entry", value: "public");
  script_add_preference(name: "UDP port :", type: "entry", value: "161");

  script_add_preference(name: "SNMPv3 user name :", type: "entry", value: "");
  script_add_preference(name: "SNMPv3 authentication password :", type: "password", value: "");
  script_add_preference(name: "SNMPv3 authentication algorithm :", type: "radio", value: "MD5;SHA1");
  script_add_preference(name: "SNMPv3 privacy password :", type: "password", value: "");
  script_add_preference(name: "SNMPv3 privacy algorithm :", type: "radio", value: "DES");

  exit(0);
}

include ("global_settings.inc");
include ("snmp_func.inc");
include ("misc_func.inc");

function do_initial_snmp_get( community, port )
{
  local_var soc, index;
  soc = open_sock_udp( port );
  if ( ! soc )
    exit(0);
  index = snmp_request( socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2 );
  close(soc);
  return index;
}

index = community = NULL;
port = script_get_preference("UDP port :");
if (!port)
   port = 161;

# SNMPv3
snmpv3_user = script_get_preference("SNMPv3 user name :");
snmpv3_auth = script_get_preference("SNMPv3 authentication password :");
snmpv3_aalg = script_get_preference("SNMPv3 authentication algorithm :");
snmpv3_priv = script_get_preference("SNMPv3 privacy password :");
snmpv3_palg = script_get_preference("SNMPv3 privacy algorithm :");

if ( snmpv3_user )
  set_kb_item( name:"SNMP/v3/username", value:snmpv3_user );

# Determine what level of SNMPv3 authentication has been requested.
if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg && snmpv3_priv && snmpv3_palg )
  snmpv3_security_level = USM_LEVEL_AUTH_PRIV;   # authPriv
else if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg )
  snmpv3_security_level = USM_LEVEL_AUTH_NO_PRIV;   # authNoPriv
else
  snmpv3_security_level = USM_LEVEL_NO_AUTH_NO_PRIV;   # noAuthNoPriv

if ( snmpv3_security_level )
{
  auth_blob = base64( str:string( snmpv3_user, ';',
                                  snmpv3_auth, ';',
                                  snmpv3_aalg, ';',
                                  snmpv3_priv, ';',
                                  snmpv3_palg, ';',
                                  snmpv3_security_level ) );
  community = string( ';', auth_blob );
  SNMP_VERSION = 3; # SNMPv3
  index = do_initial_snmp_get( community:community, port:port );
}

community_v1_v2c = script_get_preference( 'Community name :' );
if ( isnull( community_v1_v2c ) )
  community_v1_v2c = "public";

if (isnull(index))
{
  SNMP_VERSION = 1; # SNMPv2c
  index = do_initial_snmp_get( community:community_v1_v2c, port:port );
  if  ( index )
    community = community_v1_v2c;
}

if (isnull(index))
{
  SNMP_VERSION = 0; # SNMPv1
  index = do_initial_snmp_get( community:community_v1_v2c, port:port );
  if  ( index )
    community = community_v1_v2c;
}

if (isnull(index))
  exit ( 0, 'Not able to authenticate via SNMP' );

set_kb_item( name:"SNMP/community", value:community );
set_kb_item( name:"SNMP/community_v1_v2c", value:community_v1_v2c );
set_kb_item( name:"SNMP/port", value:port );
set_kb_item( name:"SNMP/version", value:SNMP_VERSION );
register_service(port:port, proto:"snmp", ipproto:"udp");
