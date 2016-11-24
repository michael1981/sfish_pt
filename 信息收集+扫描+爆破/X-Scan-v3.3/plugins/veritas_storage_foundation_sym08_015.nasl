#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33900);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-3703");
  script_bugtraq_id(30596);
  script_xref(name:"OSVDB", value:"47473");
  script_xref(name:"Secunia", value:"31486");

  script_name(english:"Veritas Storage Foundation NULL NTLMSSP Authentication Bypass (SYM08-015)");
  script_summary(english:"Checks VxSchedService.exe version"); 
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of the Scheduler Service component installed as part of
Veritas Storage Foundation for Windows on the remote host allows NULL
NTLMSSP authentication.  Provided he can send requests to the TCP
service listening on port 4888, a remote attacker can leverage this
issue to add, modify, or delete snapshot schedules and consequently to
run arbitrary code on the affected host under the context of the
SYSTEM user." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-053" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495487/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/security/Content/2008.08.14a.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch as discussed in the vendor's advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("veritas_storage_foundation_detect.nasl");
  script_require_keys("VERITAS/VeritasSchedulerService");
  script_require_ports(4888);

  exit(0);
}


include ("raw.inc");
include ("smb_func.inc");

global_var enc_arcS, enc_arcS2, enc_i, enc_j;


function initialize_key (key, constant)
{
 return MD5 (
	key +
	constant +
	raw_string(0)  # NULL end char
	);
};

function arcfour_enc_setkey (key)
{
 local_var i,j,temp;

 enc_arcS = NULL;
 for (i=0; i < 256; i++)
 {
  enc_arcS[i] = i;
  enc_arcS2[i] = ord(key[i % strlen(key)]);
 }

 j = 0;
 
 for (i=0; i < 256; i++)
 {
  j = (j + enc_arcS[i] + enc_arcS2[i]) % 256;
  temp = enc_arcS[i];
  enc_arcS[i] = enc_arcS[j];
  enc_arcS[j] = temp;
 }

 enc_i = enc_j = 0;
}


function arcfour_encrypt (data)
{
 local_var temp,t,k,output,l;

 output = NULL;
 
 for (l=0; l < strlen(data); l++)
 {
  enc_i = (enc_i+1) % 256;
  enc_j = (enc_j + enc_arcS[enc_i]) % 256;
  temp = enc_arcS[enc_i];
  enc_arcS[enc_i] = enc_arcS[enc_j];
  enc_arcS[enc_j] = temp;
  t = (enc_arcS[enc_i] + enc_arcS[enc_j]) % 256;
  k = enc_arcS[t];

  output += raw_string (k ^ ord(data[l]));
 }

 return output;
}


function initialize_ntlmssp_null()
{
 local_var key, keys;
 local_var ctssign, stcsign;
 local_var ctsseal, stcseal;

 key = crap(data:'\0', length:0x10);

 ctssign = initialize_key (key:key, constant:"session key to client-to-server signing key magic constant");
 stcsign = initialize_key (key:key, constant:"session key to server-to-client signing key magic constant");

 key = crap(data:'\0', length:0x5);

 ctsseal = initialize_key (key:key, constant:"session key to client-to-server sealing key magic constant");
 stcseal = initialize_key (key:key, constant:"session key to server-to-client sealing key magic constant");

 keys = mklist (ctssign, stcsign, ctsseal, stcseal);

 return keys;
}


function sched_sendrecv(socket, code, guid, data)
{
 local_var len;

 len = strlen(data);

 data = 
	mkdword(len) +
	mkdword(code) +
	mkdword(0) +
        guid +
	mkbyte(0) +
	data;

 send(socket:socket, data:data);
 data = recv(socket:socket, length:51, min:51);
 if (strlen(data) < 51)
   return NULL;

 len = getdword(blob:data, pos:0);
 if (len > 10000)
   return NULL;

 code = getdword(blob:data, pos:4);
 data = recv(socket:socket, length:len);

 return mklist(code,data);
}


port = get_kb_item("VERITAS/VeritasSchedulerService");
if (!port) port = 4888;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = ntlmssp_negotiate_securityblob();
len = strlen(req);


ret = sched_sendrecv(socket:soc, code:0x10, guid:"{c15f4527-3d6c-167b-f9c2-ca3908613b5a}", data:req);
if (isnull(ret) || ret[0] != 0x20) exit(0);

ret = ntlmssp_parse_challenge(data:ret[1]);
if (isnull(ret)) exit(0);

nd = ntlmssp_auth_securityblob();

keys = initialize_ntlmssp_null();

sid = 0;

arcfour_enc_setkey (key:keys[2]);
#arcfour_dec_setkey (key:keys[3]);

req = nd[1];

len = strlen(req);

data = 
	mkdword(len) +
	mkdword(0x10) +
	mkdword(0) +
        "{c15f4527-3d6c-167b-f9c2-ca3908613b5a}" +
	mkbyte(0) +
	req;


ret = sched_sendrecv(socket:soc, code:0x10, guid:"{c15f4527-3d6c-167b-f9c2-ca3908613b5a}", data:req);
if (isnull(ret) || ret[0] != 0x20 || isnull(ret[1])) exit(0);

ret = ntlmssp_parse_response(data:ret[1]);
if (!isnull(ret) && (ret == 0)) # Accept Completed
{
 filter = "src host " + get_host_ip() + " and src port " + port + " and dst port " + get_source_port(soc) + " and tcp";
 ret = send_capture(socket:soc, data:"nessus", pcap_filter:filter);
 if (ret == NULL) exit(0);

 pkt = packet_split(ret);
 tcp = pkt[1];

 tcp = tcp["data"];

 if (! (tcp["th_flags"] & (TH_FIN|TH_RST )) )
   security_hole(port);
}
