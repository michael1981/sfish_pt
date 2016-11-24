#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(12218);
 script_version("$Revision: 1.19 $");

 script_name(english:"mDNS Detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain information about the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service understands the Bonjour (also known as ZeroConf or
mDNS) protocol, which allows anyone to uncover information from the
remote host such as its operating system type and exact version, its
hostname, and the list of services it is running." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to UDP port 5353 if desired." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 summary["english"] = "mDNS detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("dns_func.inc");

port = 5353;
if(!get_udp_port_state(port))exit(0);

seen_mdns = 0;

# Many Windows-PC have iTunes installed, so we attempt to detect it
domain[0] = string("_daap");      dsz[0] = strlen(domain[0]);
domain[1] = string("_tcp");   dsz[1] = strlen(domain[1]);
domain[2] = string("local");      dsz[2] = strlen(domain[2]);

req = raw_string(
0x00,0x4a,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
req += raw_string(0x00,0x00,0x0c,0x00,0x01);

soc = open_sock_udp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096, timeout:2);
if ( r ) seen_mdns ++;



# MacOS only
domain[0] = string("_workstation");      dsz[0] = strlen(domain[0]);
domain[1] = string("_tcp");   dsz[1] = strlen(domain[1]);
domain[2] = string("local");      dsz[2] = strlen(domain[2]);



# Step[0] let's try to insert this value into the cache 
req = raw_string(
0x00,0x4a,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
req += raw_string(0x00,0x00,0x0c,0x00,0x01);

send(socket:soc, data:req);
r = recv(socket:soc, length:4096, timeout:3);
if ( strlen(r) > 7 ) answers = (ord(r[6]) * 256) + ord(r[7]);
else answers = 0;
if ( ! r || answers == 0 )
{ 
 if ( seen_mdns )
   security_warning(port:port, proto:"udp");

 exit(0);
}


if ( strlen(r) > 53 )
{
 contents = dns_split(r);
 full_name = dns_str_get(str:contents["an_rr_data_0_data"], blob:r);
 ethernet = ereg_replace(pattern:".*\[(.*)\].*", string:full_name, replace:"\1");
 name     = ereg_replace(pattern:"(.*) \[.*", string:full_name, replace:"\1");


 
 for ( i = 0 ; i < 4 ; i ++ )
 {
  if  ( contents["ad_rr_data_" + i + "_type"]  == 0x0021 ) 
	{
	 target = contents["ad_rr_data_" + i + "_data"];
	 target = substr(target, 6, strlen(target) - 1);
         name =   dns_str_get(str:target, blob:r); 
	 got_better_name ++;
	}
 }

 if (! isnull(name) ) set_kb_item(name:"mDNS/name", value:name);
 if (! isnull(ethernet) ) set_kb_item(name:"mDNS/ethernet", value:ethernet);

 if ( ! got_better_name ) name += '.local.';


 # Now, query the host info

 array = split(name, sep:'.', keep:FALSE);
 for ( i = 0 ; i < max_index(array) ; i ++ )
 {
  domain[i] = array[i];
  dsz[i]    = strlen(domain[i]);
 }

 domain[i] = NULL;



 req = raw_string(
0x00,0x4A,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
 for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
 req += raw_string(0x00,0x00,0x0d,0x00,0x01);

 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);
 if ( strlen(r) > 7 ) answers = (ord(r[6]) * 256) + ord(r[7]);
 else answers = 0;
 if ( answers )
 {
 if ( strlen(r) <= 12 ) exit(0);
 len = ord(r[12]);

 offset = 13 + len + 23;
 if ( strlen(r) <= offset ) exit(0);
 cpu_len = ord(r[offset]);
 cpu_type = substr(r, offset + 1, offset + cpu_len);
 if ( !isnull(cpu_type) ) set_kb_item(name:"mDNS/cpu", value:cpu_type);

 offset += cpu_len + 1;
 os = substr(r, offset + 1, offset + ord(r[offset]));
 p = strstr(os, " (");
 if ( p ) os -= p;

 if ( !isnull(os)) set_kb_item(name:"mDNS/os", value:os);
 }

report = string ("\n",
		"Nessus was able to extract the following information :\n\n",
		"  - Computer name    : " , name , "\n",
		"  - Ethernet addr    : " , ethernet , "\n");

 if ( cpu_type ) report += string("  - Computer Type    : " , cpu_type , "\n");
 if ( os ) report += string("  - Operating System : " , os , "\n");

security_warning(extra:report, port:port, proto:"udp");
register_service(port:5353, proto:"mdns", ipproto:"udp");

}
