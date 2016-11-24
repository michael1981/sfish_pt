#TRUSTED 7f58afd4ff93a4c194e9480dde3302d752cbba7494ed4fea85c0e6a8dc36c5141b8b7d4b11f6bfe8dc6e6640b5c2dbf8b5e1968a8a0e62082f12538b419471b8a486d00f08416121a83bfe23d2ca8cbfa80945b9d2e0dca2820a8b436c134ec01f354e9c413cd394a4f056f1c2aaf66e3dcfabb3ba2b2fb1237b1d1342a67e2230a3e594c1f724f8a3688b8ccc2ee1c41dee4671a6d51903eb2ca603679a2eaba49593124dd50aaaab6ad9738abae81e9f7a122d7d7ae73252c7319708e3d2fd167805339c8832d4370872eb29e531735a8c5557f534cfe29a69e376b64ef395add622e409023f223ca768c0c3b8cd703c3649fd546ed20301e3bfeea3dedcffcaf241866c602d9d996adf86e166ad9b0326bf85d2094637dd0c2d8bff769de97d9158d8160fd29cae5976a8e9bda02ec054996a0b67adf888d1dbe08efa7283364e38daf239d1d515e1fb3f196dd1f11717c76988ee5fc5e86361dac3e538063ea3dd36095fb6cceae4da36413e4149b1608b6bf9e59921844a6970bab71bee638967c11a76ec1e4ba2d513b3278cc4a94506095ce70c0e01dfaeea47b5baf3301becddaad32c31045dd9f33ffe1aecf86a456bb51743f130a35f2c6d4b6dd5d72e02f95b87217aebbfcd7611046730b626157d38f0afe002f35e10a8a2e06bece575404dc99480837332678c46ef00e9a0ae19e9f2366e37e6035dfb27f4fe
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 2202 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17351);
 script_version ("1.3");
 name["english"] = "Kerberos configuration";
 
 script_name(english:name["english"]);
 script_summary(english:"Fills kerberos information in the KB");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin is used to configure Kerberos server settings."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"This plugin lets a user enter information about the Kerberos server
that will be queried by some scripts (SMB at this time) to log into
the remote hosts."
 );
 script_set_attribute(
  attribute:"solution", 
  value:"n/a"
 );
 script_set_attribute(
  attribute:"risk_factor", 
  value:"None"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2005/03/17"
 );
 script_end_attributes();
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 script_add_preference(name:"Kerberos Key Distribution Center (KDC) :", type:"entry", value:"");
 script_add_preference(name:"Kerberos KDC Port :", type:"entry", value:"88");
 script_add_preference(name:"Kerberos KDC Transport :", type:"radio", value:"udp;tcp");
 script_add_preference(name:"Kerberos Realm (SSH only) :", type:"entry", value:"");
 exit(0);
}



kdc = script_get_preference("Kerberos Key Distribution Center (KDC) :");
if ( ! kdc ) exit(0);

kdc_port = int(script_get_preference("Kerberos KDC Port :"));
if ( kdc_port <= 0 ) exit(0);

kdc_realm = script_get_preference("Kerberos Realm (SSH only) :");
if ( kdc_realm ) set_kb_item(name:"Secret/SSH/realm", value:kdc_realm);

set_kb_item(name:"Secret/kdc_hostname", value:kdc);
set_kb_item(name:"Secret/kdc_port", value:kdc_port);

kdc_transport =  script_get_preference("Kerberos KDC Transport :");
if ( kdc_transport == "tcp" ) 
 set_kb_item(name:"Secret/kdc_use_tcp", value:TRUE);


